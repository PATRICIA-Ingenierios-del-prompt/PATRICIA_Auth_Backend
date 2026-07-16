package com.escuelaing.auth.controller;

import com.escuelaing.auth.dto.request.JuradoLoginRequest;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;

    @PostMapping("/login/microsoft")
    public TokenResponse loginMicrosoft(
            @Valid @RequestBody MicrosoftCodeRequest request,
            HttpServletRequest httpRequest
    ) {
        return authService.loginMicrosoft(
                request.code(),
                request.redirectUri(),
                clientIp(httpRequest)
        );
    }

    @PostMapping("/login/jurado")
    public TokenResponse loginJurado(
            @Valid @RequestBody JuradoLoginRequest request,
            HttpServletRequest httpRequest
    ) {
        return authService.loginJurado(
                request.email(),
                request.password(),
                clientIp(httpRequest)
        );
    }

    @PostMapping("/otp/request")
    public ResponseEntity<Void> requestOtp(
            @Valid @RequestBody OtpRequestRequest request
    ) {
        authService.requestOtp(request.email());
        return ResponseEntity.accepted().build();
    }

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

    @PostMapping("/refresh")
    public TokenResponse refresh(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        return authService.refresh(request.refreshToken());
    }

    @PostMapping("/validate")
    public Map<String, Object> validate(
            @Valid @RequestBody ValidateTokenRequest request
    ) {
        return jwtService.introspect(request.token());
    }

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
