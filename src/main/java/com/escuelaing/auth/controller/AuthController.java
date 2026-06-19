package com.escuelaing.auth.controller;

import com.escuelaing.auth.dto.request.LogoutRequest;
import com.escuelaing.auth.dto.request.MicrosoftCodeRequest;
import com.escuelaing.auth.dto.request.OtpRequestRequest;
import com.escuelaing.auth.dto.request.OtpVerifyRequest;
import com.escuelaing.auth.dto.request.RefreshTokenRequest;
import com.escuelaing.auth.dto.request.ValidateTokenRequest;
import com.escuelaing.auth.dto.response.TokenResponse;
import com.escuelaing.auth.service.AuthService;
import com.escuelaing.auth.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtService  jwtService;

    /**
     * Login con Microsoft OAuth2.
     * Recibe el authorization_code y devuelve JWT + refresh token.
     */
    @PostMapping("/login/microsoft")
    public TokenResponse loginMicrosoft(
            @Valid @RequestBody MicrosoftCodeRequest request,
            HttpServletRequest httpRequest
    ) {
        return authService.loginMicrosoft(
                request.code(),
                clientIp(httpRequest)
        );
    }

    /**
     * Solicita el envío de un código OTP al correo institucional.
     * Primera fase del login por OTP (segunda opción de ingreso).
     */
    @PostMapping("/otp/request")
    public ResponseEntity<Void> requestOtp(
            @Valid @RequestBody OtpRequestRequest request
    ) {
        authService.requestOtp(request.email());
        return ResponseEntity.accepted().build();
    }

    /**
     * Verifica el código OTP y emite JWT + refresh token.
     * Segunda fase del login por OTP.
     */
    @PostMapping("/otp/verify")
    public TokenResponse verifyOtp(
            @Valid @RequestBody OtpVerifyRequest request,
            HttpServletRequest httpRequest
    ) {
        return authService.loginOtp(
                request.email(),
                request.code(),
                clientIp(httpRequest)
        );
    }

    /**
     * Refresco de sesión con rotación obligatoria del refresh token.
     */
    @PostMapping("/refresh")
    public TokenResponse refresh(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        return authService.refresh(request.refreshToken());
    }

    /**
     * Validación / introspección de JWT propio.
     * Útil para debug y pruebas Swagger.
     */
    @PostMapping("/validate")
    public Map<String, Object> validate(
            @Valid @RequestBody ValidateTokenRequest request
    ) {
        return jwtService.introspect(request.token());
    }

    /**
     * Logout.
     * Con header X-Forced: true invalida TODAS las sesiones del usuario.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @Valid @RequestBody LogoutRequest request,
            @RequestHeader(value = "X-Forced", defaultValue = "false") boolean forced
    ) {
        authService.logout(request.refreshToken(), forced);
        return ResponseEntity.noContent().build();
    }

    private String clientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
