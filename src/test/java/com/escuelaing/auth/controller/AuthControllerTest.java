package com.escuelaing.auth.controller;

import com.escuelaing.auth.config.SecurityConfig;
import com.escuelaing.auth.dto.response.TokenResponse;
import com.escuelaing.auth.exception.GlobalExceptionHandler;
import com.escuelaing.auth.exception.InvalidJuradoCredentialsException;
import com.escuelaing.auth.exception.InvalidOtpException;
import com.escuelaing.auth.exception.InvalidRefreshTokenException;
import com.escuelaing.auth.exception.OtpRequestException;
import com.escuelaing.auth.security.InternalApiKeyFilter;
import com.escuelaing.auth.service.AuthService;
import com.escuelaing.auth.service.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Import({SecurityConfig.class, InternalApiKeyFilter.class, GlobalExceptionHandler.class})
@ActiveProfiles("test")
class AuthControllerTest {

    @Autowired MockMvc mockMvc;

    @MockBean AuthService authService;
    @MockBean JwtService jwtService;

    private static final TokenResponse TOKEN = TokenResponse.builder()
            .accessToken("access-token")
            .refreshToken("refresh-token")
            .tokenType("Bearer")
            .expiresIn(900L)
            .build();

    // -------------------------------------------------------------------------
    // POST /auth/login/microsoft
    // -------------------------------------------------------------------------

    @Test
    void loginMicrosoft_returns200_withTokens() throws Exception {
        when(authService.loginMicrosoft(eq("auth-code"), any(), anyString())).thenReturn(TOKEN);

        mockMvc.perform(post("/auth/login/microsoft")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"code":"auth-code"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900));
    }

    @Test
    void loginMicrosoft_returns400_whenCodeIsBlank() throws Exception {
        mockMvc.perform(post("/auth/login/microsoft")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"code":""}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginMicrosoft_extractsIpFromXForwardedFor() throws Exception {
        when(authService.loginMicrosoft(eq("code"), any(), eq("10.0.0.1"))).thenReturn(TOKEN);

        mockMvc.perform(post("/auth/login/microsoft")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", "10.0.0.1, 192.168.1.1")
                        .content("""
                                {"code":"code"}
                                """))
                .andExpect(status().isOk());

        verify(authService).loginMicrosoft(eq("code"), any(), eq("10.0.0.1"));
    }

    // -------------------------------------------------------------------------
    // POST /auth/login/jurado
    // -------------------------------------------------------------------------

    @Test
    void loginJurado_returns200_withTokens() throws Exception {
        when(authService.loginJurado(eq("jurado@ejemplo.com"), eq("secret"), anyString()))
                .thenReturn(TOKEN);

        mockMvc.perform(post("/auth/login/jurado")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"jurado@ejemplo.com","password":"secret"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"));
    }

    @Test
    void loginJurado_returns400_whenEmailIsInvalid() throws Exception {
        mockMvc.perform(post("/auth/login/jurado")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"not-an-email","password":"secret"}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginJurado_returns400_whenPasswordIsBlank() throws Exception {
        mockMvc.perform(post("/auth/login/jurado")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"jurado@ejemplo.com","password":""}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginJurado_returns401_whenCredentialsAreInvalid() throws Exception {
        doThrow(new InvalidJuradoCredentialsException("Correo o contraseña incorrectos"))
                .when(authService).loginJurado(any(), any(), any());

        mockMvc.perform(post("/auth/login/jurado")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"jurado@ejemplo.com","password":"wrong"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("UNAUTHORIZED"));
    }

    // -------------------------------------------------------------------------
    // POST /auth/otp/request
    // -------------------------------------------------------------------------

    @Test
    void requestOtp_returns202_onSuccess() throws Exception {
        mockMvc.perform(post("/auth/otp/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"user@escuelaing.edu.co"}
                                """))
                .andExpect(status().isAccepted());

        verify(authService).requestOtp("user@escuelaing.edu.co");
    }

    @Test
    void requestOtp_returns400_whenEmailIsInvalid() throws Exception {
        mockMvc.perform(post("/auth/otp/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"not-an-email"}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void requestOtp_returns400_whenEmailIsBlank() throws Exception {
        mockMvc.perform(post("/auth/otp/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":""}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void requestOtp_returns429_whenCooldownActive() throws Exception {
        doThrow(new OtpRequestException("Debes esperar"))
                .when(authService).requestOtp(any());

        mockMvc.perform(post("/auth/otp/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"user@escuelaing.edu.co"}
                                """))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error").value("TOO_MANY_REQUESTS"));
    }

    // -------------------------------------------------------------------------
    // POST /auth/otp/verify
    // -------------------------------------------------------------------------

    @Test
    void verifyOtp_returns200_withTokens() throws Exception {
        when(authService.loginOtp(eq("user@escuelaing.edu.co"), eq("123456"), anyString()))
                .thenReturn(TOKEN);

        mockMvc.perform(post("/auth/otp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"user@escuelaing.edu.co","code":"123456"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access-token"));
    }

    @Test
    void verifyOtp_returns400_whenCodeIsNotNumeric() throws Exception {
        mockMvc.perform(post("/auth/otp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"user@escuelaing.edu.co","code":"abc123"}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void verifyOtp_returns401_whenOtpIsInvalid() throws Exception {
        doThrow(new InvalidOtpException("Código inválido"))
                .when(authService).loginOtp(any(), any(), any());

        mockMvc.perform(post("/auth/otp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"user@escuelaing.edu.co","code":"000000"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("UNAUTHORIZED"));
    }

    // -------------------------------------------------------------------------
    // POST /auth/refresh
    // -------------------------------------------------------------------------

    @Test
    void refresh_returns200_withNewTokens() throws Exception {
        when(authService.refresh("old-refresh")).thenReturn(TOKEN);

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"old-refresh"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"));
    }

    @Test
    void refresh_returns400_whenRefreshTokenIsBlank() throws Exception {
        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":""}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void refresh_returns401_whenTokenIsInvalid() throws Exception {
        doThrow(new InvalidRefreshTokenException("Token expirado"))
                .when(authService).refresh(any());

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"expired"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("UNAUTHORIZED"));
    }

    // -------------------------------------------------------------------------
    // POST /auth/validate
    // -------------------------------------------------------------------------

    @Test
    void validate_returns200_withIntrospectionResult() throws Exception {
        when(jwtService.introspect("my-token"))
                .thenReturn(Map.of("valid", true, "sub", "user-id",
                        "email", "u@escuelaing.edu.co", "roles", List.of("USER")));

        mockMvc.perform(post("/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"my-token"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.email").value("u@escuelaing.edu.co"));
    }

    @Test
    void validate_returns200_withValidFalse_forExpiredToken() throws Exception {
        when(jwtService.introspect("expired"))
                .thenReturn(Map.of("valid", false, "reason", "expired"));

        mockMvc.perform(post("/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"expired"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.reason").value("expired"));
    }

    // -------------------------------------------------------------------------
    // POST /auth/logout
    // -------------------------------------------------------------------------

    @Test
    void logout_returns204_onSuccess() throws Exception {
        mockMvc.perform(post("/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"my-token"}
                                """))
                .andExpect(status().isNoContent());

        verify(authService).logout("my-token", false);
    }

    @Test
    void logout_returns204_withForcedHeader() throws Exception {
        mockMvc.perform(post("/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forced", "true")
                        .content("""
                                {"refreshToken":"my-token"}
                                """))
                .andExpect(status().isNoContent());

        verify(authService).logout("my-token", true);
    }

    @Test
    void logout_returns400_whenRefreshTokenIsBlank() throws Exception {
        mockMvc.perform(post("/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":""}
                                """))
                .andExpect(status().isBadRequest());
    }
}