package com.escuelaing.auth.service;

import com.escuelaing.auth.dto.event.AuthEvent;
import com.escuelaing.auth.dto.response.TokenResponse;
import com.escuelaing.auth.dto.usuario.FindOrCreateUserRequest;
import com.escuelaing.auth.dto.usuario.UsuarioResponse;
import com.escuelaing.auth.exception.InvalidDomainException;
import com.escuelaing.auth.exception.InvalidOtpException;
import com.escuelaing.auth.exception.InvalidRefreshTokenException;
import com.escuelaing.auth.messaging.AuthEventPublisher;
import com.escuelaing.auth.mock.MockUsuarioClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final MicrosoftOAuthService microsoftOAuthService;
    private final MockUsuarioClient mockUsuarioClient;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final OtpService otpService;
    private final DomainValidationService domainValidationService;
    private final AuthEventPublisher eventPublisher;

    public TokenResponse loginMicrosoft(String code, String ip) {

        Map<String, Object> microsoftUser =
                microsoftOAuthService.authenticate(code);
        String email = (String) microsoftUser.get("email");

        try {
            domainValidationService.validate(email);
        } catch (InvalidDomainException e) {
            publishAuthFailed(email, "DOMINIO_NO_PERMITIDO", null);
            throw e;
        }

        UsuarioResponse usuario = mockUsuarioClient.findOrCreate(
                new FindOrCreateUserRequest(
                        email,
                        (String) microsoftUser.get("name"),
                        (String) microsoftUser.get("microsoftId")
                )
        );

        TokenResponse response = buildTokenResponse(usuario);
        publishSessionStarted(usuario, "MICROSOFT", ip);
        return response;
    }

    public void requestOtp(String email) {
        try {
            domainValidationService.validate(email);
            otpService.requestOtp(email);
            publishOtpRequested(email);
        } catch (InvalidDomainException e) {
            publishAuthFailed(email, "DOMINIO_NO_PERMITIDO", null);
            throw e;
        }
    }

    public TokenResponse loginOtp(String email, String code, String ip) {

        try {
            domainValidationService.validate(email);
            otpService.verify(email, code);
        } catch (InvalidDomainException e) {
            publishAuthFailed(email, "DOMINIO_NO_PERMITIDO", null);
            throw e;
        } catch (InvalidOtpException e) {
            publishAuthFailed(email, otpFailureReason(e), null);
            throw e;
        }

        String normalized = email.toLowerCase();
        UsuarioResponse usuario = mockUsuarioClient.findOrCreate(
                new FindOrCreateUserRequest(
                        normalized,
                        deriveName(normalized),
                        null
                )
        );

        log.info("OTP login successful for email={}", normalized);
        TokenResponse response = buildTokenResponse(usuario);
        publishSessionStarted(usuario, "OTP", ip);
        return response;
    }

    public TokenResponse refresh(String refreshToken) {

        String userId = refreshTokenService.validate(refreshToken);

        if (userId == null) {
            publishAuthFailed(null, "REFRESH_INVALIDO", null);
            throw new InvalidRefreshTokenException(
                    "Refresh token invalido o expirado"
            );
        }

        UsuarioResponse usuario = mockUsuarioClient.findById(userId);

        String newRefreshToken = refreshTokenService.rotate(
                refreshToken,
                userId
        );

        String accessToken = jwtService.generateToken(usuario);

        log.info("Session refreshed for userId={}", userId);

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getExpirationSeconds())
                .build();
    }

    public void logout(String refreshToken, boolean forced) {

        String userId = refreshTokenService.validate(refreshToken);

        if (userId == null) {
            log.warn("Logout with unknown/expired refresh token");
            return;
        }

        if (forced) {
            long invalidated = refreshTokenService.invalidateAllSessions(userId);
            publishSessionClosedForced(
                    userId,
                    "LOGOUT_FORZADO",
                    invalidated
            );
            log.info("Forced logout: all sessions closed for userId={}", userId);
        } else {
            refreshTokenService.invalidateToken(refreshToken, userId);
            publishSessionClosed(userId);
            log.info("Logout: single session closed for userId={}", userId);
        }
    }

    public void forceCloseAllSessions(String userId) {
        long invalidated = refreshTokenService.invalidateAllSessions(userId);
        publishSessionClosedForced(
                userId,
                "CIERRE_ADMINISTRATIVO",
                invalidated
        );
        log.info("Admin forced close all sessions for userId={}", userId);
    }

    private String deriveName(String email) {
        int at = email.indexOf('@');
        return at > 0 ? email.substring(0, at) : email;
    }

    private TokenResponse buildTokenResponse(UsuarioResponse usuario) {

        String accessToken = jwtService.generateToken(usuario);
        String refreshToken = refreshTokenService.create(
                usuario.id().toString()
        );

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getExpirationSeconds())
                .build();
    }

    private void publishSessionStarted(
            UsuarioResponse usuario,
            String metodo,
            String ip
    ) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("email", usuario.email());
        payload.put("metodo", metodo);
        if (ip != null && !ip.isBlank()) {
            payload.put("ip", ip);
        }

        eventPublisher.publish(
                "sesion.iniciada",
                event(usuario.id(), "sesion.iniciada", payload)
        );
    }

    private void publishSessionClosed(String userId) {
        eventPublisher.publish(
                "sesion.cerrada",
                event(
                        UUID.fromString(userId),
                        "sesion.cerrada",
                        Map.of("motivo", "LOGOUT_VOLUNTARIO")
                )
        );
    }

    private void publishSessionClosedForced(
            String userId,
            String motivo,
            long sesionesInvalidadas
    ) {
        eventPublisher.publish(
                "sesion.cerrada.forzada",
                event(
                        UUID.fromString(userId),
                        "sesion.cerrada.forzada",
                        Map.of(
                                "motivo", motivo,
                                "sesionesInvalidadas", sesionesInvalidadas
                        )
                )
        );
    }

    private void publishOtpRequested(String email) {
        eventPublisher.publish(
                "otp.solicitado",
                event(
                        null,
                        "otp.solicitado",
                        Map.of("email", email.toLowerCase())
                )
        );
    }

    private void publishAuthFailed(
            String email,
            String motivo,
            Integer intentos
    ) {
        Map<String, Object> payload = new HashMap<>();
        if (email != null) {
            payload.put("email", email.toLowerCase());
        }
        payload.put("motivo", motivo);
        if (intentos != null) {
            payload.put("intentos", intentos);
        }

        eventPublisher.publish(
                "auth.fallido",
                event(null, "auth.fallido", payload)
        );
    }

    private String otpFailureReason(InvalidOtpException exception) {
        String message = exception.getMessage();
        if (message != null && message.toLowerCase().contains("intentos")) {
            return "MAX_INTENTOS";
        }
        return "OTP_INVALIDO";
    }

    private AuthEvent event(
            UUID usuarioId,
            String tipo,
            Map<String, Object> payload
    ) {
        return new AuthEvent(
                UUID.randomUUID(),
                Instant.now(),
                usuarioId,
                tipo,
                payload
        );
    }
}