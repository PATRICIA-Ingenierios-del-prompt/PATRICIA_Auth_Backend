package com.escuelaing.auth.controller;

import com.escuelaing.auth.dto.request.LogoutRequest;
import com.escuelaing.auth.dto.request.MicrosoftCodeRequest;
import com.escuelaing.auth.dto.request.RefreshTokenRequest;
import com.escuelaing.auth.dto.request.ValidateTokenRequest;
import com.escuelaing.auth.dto.response.TokenResponse;
import com.escuelaing.auth.service.AuthService;
import com.escuelaing.auth.service.JwtService;
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
            @Valid @RequestBody MicrosoftCodeRequest request
    ) {
        return authService.loginMicrosoft(request.code());
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
}