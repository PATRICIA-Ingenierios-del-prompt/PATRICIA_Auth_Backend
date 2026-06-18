package com.escuelaing.auth.service;

import com.escuelaing.auth.dto.response.TokenResponse;
import com.escuelaing.auth.dto.usuario.FindOrCreateUserRequest;
import com.escuelaing.auth.dto.usuario.UsuarioResponse;
import com.escuelaing.auth.exception.InvalidDomainException;
import com.escuelaing.auth.exception.InvalidRefreshTokenException;
import com.escuelaing.auth.mock.MockUsuarioClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final MicrosoftOAuthService microsoftOAuthService;
    private final MockUsuarioClient      mockUsuarioClient;
    private final JwtService             jwtService;
    private final RefreshTokenService    refreshTokenService;
    private final OtpService             otpService;

    @Value("${security.allowed-domain}")
    private String allowedDomain;

    /**
     * Login Microsoft completo.
     * Emite JWT real + refresh token opaco guardado en Redis.
     */
    public TokenResponse loginMicrosoft(String code) {

        Map<String, Object> microsoftUser =
                microsoftOAuthService.authenticate(code);

        UsuarioResponse usuario = mockUsuarioClient.findOrCreate(
                new FindOrCreateUserRequest(
                        (String) microsoftUser.get("email"),
                        (String) microsoftUser.get("name"),
                        (String) microsoftUser.get("microsoftId")
                )
        );

        return buildTokenResponse(usuario);
    }

    /**
     * Solicita un código OTP para el correo institucional.
     * Segunda opción de ingreso, independiente de Microsoft OAuth.
     */
    public void requestOtp(String email) {
        validateInstitutionalDomain(email);
        otpService.requestOtp(email);
    }

    /**
     * Login con OTP: verifica el código y emite JWT + refresh token.
     */
    public TokenResponse loginOtp(String email, String code) {

        validateInstitutionalDomain(email);
        otpService.verify(email, code);

        String normalized = email.toLowerCase();
        UsuarioResponse usuario = mockUsuarioClient.findOrCreate(
                new FindOrCreateUserRequest(
                        normalized,
                        deriveName(normalized),
                        null
                )
        );

        log.info("OTP login successful for email={}", normalized);
        return buildTokenResponse(usuario);
    }

    /**
     * Refresca la sesión con rotación obligatoria del refresh token.
     * El token viejo se invalida inmediatamente.
     */
    public TokenResponse refresh(String refreshToken) {

        String userId = refreshTokenService.validate(refreshToken);

        if (userId == null) {
            throw new InvalidRefreshTokenException(
                    "Refresh token inválido o expirado"
            );
        }

        // Simular carga del usuario desde el userId
        // Cuando exista Usuario-Service, reemplazar por Feign
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
                .expiresIn(
                        jwtService.getExpirationSeconds()
                )
                .build();
    }

    /**
     * Logout: invalida el refresh token.
     * Con X-Forced: true invalida TODAS las sesiones del usuario.
     */
    public void logout(String refreshToken, boolean forced) {

        String userId = refreshTokenService.validate(refreshToken);

        if (userId == null) {
            // Token ya expirado o inválido — operación idempotente
            log.warn("Logout with unknown/expired refresh token");
            return;
        }

        if (forced) {
            refreshTokenService.invalidateAllSessions(userId);
            log.info("Forced logout: all sessions closed for userId={}", userId);
        } else {
            refreshTokenService.invalidateToken(refreshToken, userId);
            log.info("Logout: single session closed for userId={}", userId);
        }
    }

    /**
     * Cierre administrativo de todas las sesiones de un usuario.
     * Llamado desde /internal/auth/cerrar-sesion/{userId}
     */
    public void forceCloseAllSessions(String userId) {
        refreshTokenService.invalidateAllSessions(userId);
        log.info("Admin forced close all sessions for userId={}", userId);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void validateInstitutionalDomain(String email) {
        if (email == null || !email.toLowerCase().endsWith(allowedDomain)) {
            throw new InvalidDomainException(
                    "Only institutional accounts are allowed"
            );
        }
    }

    private String deriveName(String email) {
        int at = email.indexOf('@');
        return at > 0 ? email.substring(0, at) : email;
    }

    private TokenResponse buildTokenResponse(UsuarioResponse usuario) {

        String accessToken  = jwtService.generateToken(usuario);
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
}