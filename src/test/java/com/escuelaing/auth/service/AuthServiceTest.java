package com.escuelaing.auth.service;

import com.escuelaing.auth.client.UsuarioServiceClient;
import com.escuelaing.auth.dto.event.AuthEvent;
import com.escuelaing.auth.dto.response.TokenResponse;
import com.escuelaing.auth.dto.usuario.FindOrCreateUserRequest;
import com.escuelaing.auth.dto.usuario.UsuarioResponse;
import com.escuelaing.auth.exception.InvalidDomainException;
import com.escuelaing.auth.exception.InvalidJuradoCredentialsException;
import com.escuelaing.auth.exception.InvalidOtpException;
import com.escuelaing.auth.exception.InvalidRefreshTokenException;
import com.escuelaing.auth.messaging.AuthEventPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock MicrosoftOAuthService microsoftOAuthService;
    @Mock UsuarioServiceClient usuarioServiceClient;
    @Mock JwtService jwtService;
    @Mock RefreshTokenService refreshTokenService;
    @Mock OtpService otpService;
    @Mock DomainValidationService domainValidationService;
    @Mock AuthEventPublisher eventPublisher;

    AuthService authService;

    UUID userId = UUID.randomUUID();
    UsuarioResponse usuario;

    @BeforeEach
    void setUp() {
        authService = new AuthService(
                microsoftOAuthService, usuarioServiceClient, jwtService,
                refreshTokenService, otpService, domainValidationService, eventPublisher
        );
        usuario = new UsuarioResponse(userId, "student@escuelaing.edu.co", "Student", List.of("USER"), "ACTIVE");
    }

    // -------------------------------------------------------------------------
    // loginMicrosoft
    // -------------------------------------------------------------------------

    @Test
    void loginMicrosoft_returnsTokenResponse_onSuccess() {
        when(microsoftOAuthService.authenticate("code123", null))
                .thenReturn(Map.of("email", usuario.email(), "name", usuario.nombre(), "microsoftId", "ms-id"));
        when(usuarioServiceClient.findOrCreate(any())).thenReturn(usuario);
        when(jwtService.generateToken(usuario)).thenReturn("access-token");
        when(jwtService.getExpirationSeconds()).thenReturn(900L);
        when(refreshTokenService.create(userId.toString())).thenReturn("refresh-token");

        TokenResponse response = authService.loginMicrosoft("code123", null, "10.0.0.1");

        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isEqualTo("refresh-token");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo(900L);
    }

    @Test
    void loginMicrosoft_publishesSesionIniciadaEvent() {
        when(microsoftOAuthService.authenticate("code", null))
                .thenReturn(Map.of("email", usuario.email(), "name", usuario.nombre(), "microsoftId", "ms-id"));
        when(usuarioServiceClient.findOrCreate(any())).thenReturn(usuario);
        when(jwtService.generateToken(any())).thenReturn("token");
        when(jwtService.getExpirationSeconds()).thenReturn(900L);
        when(refreshTokenService.create(any())).thenReturn("refresh");

        authService.loginMicrosoft("code", null, "192.168.1.1");

        ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
        verify(eventPublisher).publish(eq("sesion.iniciada"), captor.capture());
        AuthEvent event = captor.getValue();
        assertThat(event.tipo()).isEqualTo("sesion.iniciada");
        assertThat(event.payload()).containsEntry("metodo", "MICROSOFT");
        assertThat(event.payload()).containsEntry("ip", "192.168.1.1");
    }

    @Test
    void loginMicrosoft_publishesSesionIniciadaWithoutIp_whenIpIsBlank() {
        when(microsoftOAuthService.authenticate("code", null))
                .thenReturn(Map.of("email", usuario.email(), "name", usuario.nombre(), "microsoftId", "ms-id"));
        when(usuarioServiceClient.findOrCreate(any())).thenReturn(usuario);
        when(jwtService.generateToken(any())).thenReturn("token");
        when(jwtService.getExpirationSeconds()).thenReturn(900L);
        when(refreshTokenService.create(any())).thenReturn("refresh");

        authService.loginMicrosoft("code", null, "  ");

        ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
        verify(eventPublisher).publish(eq("sesion.iniciada"), captor.capture());
        assertThat(captor.getValue().payload()).doesNotContainKey("ip");
    }

    @Test
    void loginMicrosoft_throwsInvalidDomainException_andPublishesAuthFailed() {
        when(microsoftOAuthService.authenticate("code", null))
                .thenReturn(Map.of("email", "hacker@evil.com", "name", "H", "microsoftId", "x"));
        doThrow(new InvalidDomainException("Domain not allowed"))
                .when(domainValidationService).validate("hacker@evil.com");

        assertThatThrownBy(() -> authService.loginMicrosoft("code", null, "1.2.3.4"))
                .isInstanceOf(InvalidDomainException.class);

        ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
        verify(eventPublisher).publish(eq("auth.fallido"), captor.capture());
        assertThat(captor.getValue().payload()).containsEntry("motivo", "DOMINIO_NO_PERMITIDO");
    }

    // -------------------------------------------------------------------------
    // loginJurado
    // -------------------------------------------------------------------------

    @Test
    void loginJurado_returnsTokenResponse_onSuccess() {
        when(usuarioServiceClient.loginJurado("jurado@ejemplo.com", "secret"))
                .thenReturn(usuario);
        when(jwtService.generateToken(usuario)).thenReturn("access-token");
        when(jwtService.getExpirationSeconds()).thenReturn(900L);
        when(refreshTokenService.create(userId.toString())).thenReturn("refresh-token");

        TokenResponse response = authService.loginJurado("jurado@ejemplo.com", "secret", "10.0.0.1");

        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isEqualTo("refresh-token");
    }

    @Test
    void loginJurado_normalizesEmailToLowercase() {
        when(usuarioServiceClient.loginJurado("jurado@ejemplo.com", "secret"))
                .thenReturn(usuario);
        when(jwtService.generateToken(any())).thenReturn("t");
        when(jwtService.getExpirationSeconds()).thenReturn(900L);
        when(refreshTokenService.create(any())).thenReturn("r");

        authService.loginJurado("Jurado@Ejemplo.com", "secret", "ip");

        verify(usuarioServiceClient).loginJurado("jurado@ejemplo.com", "secret");
    }

    @Test
    void loginJurado_publishesSesionIniciadaEvent_withMetodoJurado() {
        when(usuarioServiceClient.loginJurado(any(), any())).thenReturn(usuario);
        when(jwtService.generateToken(any())).thenReturn("t");
        when(jwtService.getExpirationSeconds()).thenReturn(900L);
        when(refreshTokenService.create(any())).thenReturn("r");

        authService.loginJurado("jurado@ejemplo.com", "secret", "192.168.1.1");

        ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
        verify(eventPublisher).publish(eq("sesion.iniciada"), captor.capture());
        assertThat(captor.getValue().payload()).containsEntry("metodo", "JURADO");
        assertThat(captor.getValue().payload()).containsEntry("ip", "192.168.1.1");
    }

    @Test
    void loginJurado_throwsAndPublishesAuthFailed_whenCredentialsInvalid() {
        doThrow(new InvalidJuradoCredentialsException("Correo o contraseña incorrectos"))
                .when(usuarioServiceClient).loginJurado("jurado@ejemplo.com", "wrong");

        assertThatThrownBy(() -> authService.loginJurado("jurado@ejemplo.com", "wrong", "ip"))
                .isInstanceOf(InvalidJuradoCredentialsException.class);

        ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
        verify(eventPublisher).publish(eq("auth.fallido"), captor.capture());
        assertThat(captor.getValue().payload()).containsEntry("motivo", "CREDENCIALES_INVALIDAS");
        assertThat(captor.getValue().payload()).containsEntry("email", "jurado@ejemplo.com");
    }

    // -------------------------------------------------------------------------
    // requestOtp
    // -------------------------------------------------------------------------

    @Test
    void requestOtp_callsOtpServiceAndPublishesEvent() {
        authService.requestOtp("user@escuelaing.edu.co");

        verify(otpService).requestOtp("user@escuelaing.edu.co");
        ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
        verify(eventPublisher).publish(eq("otp.solicitado"), captor.capture());
        assertThat(captor.getValue().payload()).containsEntry("email", "user@escuelaing.edu.co");
    }

    @Test
    void requestOtp_throwsAndPublishesFailedEvent_whenDomainInvalid() {
        doThrow(new InvalidDomainException("bad domain"))
                .when(domainValidationService).validate("x@bad.com");

        assertThatThrownBy(() -> authService.requestOtp("x@bad.com"))
                .isInstanceOf(InvalidDomainException.class);

        verify(eventPublisher).publish(eq("auth.fallido"), any());
        verify(otpService, never()).requestOtp(any());
    }

    // -------------------------------------------------------------------------
    // loginOtp
    // -------------------------------------------------------------------------

    @Test
    void loginOtp_returnsTokenResponse_onSuccess() {
        when(usuarioServiceClient.findOrCreate(any())).thenReturn(usuario);
        when(jwtService.generateToken(any())).thenReturn("access");
        when(jwtService.getExpirationSeconds()).thenReturn(900L);
        when(refreshTokenService.create(any())).thenReturn("refresh");

        TokenResponse response = authService.loginOtp("student@escuelaing.edu.co", "123456", "10.0.0.1");

        assertThat(response.accessToken()).isEqualTo("access");
        verify(otpService).verify("student@escuelaing.edu.co", "123456");
    }

    @Test
    void loginOtp_derivesNameFromEmail() {
        when(usuarioServiceClient.findOrCreate(any())).thenReturn(usuario);
        when(jwtService.generateToken(any())).thenReturn("t");
        when(jwtService.getExpirationSeconds()).thenReturn(900L);
        when(refreshTokenService.create(any())).thenReturn("r");

        authService.loginOtp("john.doe@escuelaing.edu.co", "000000", "ip");

        ArgumentCaptor<FindOrCreateUserRequest> captor = ArgumentCaptor.forClass(FindOrCreateUserRequest.class);
        verify(usuarioServiceClient).findOrCreate(captor.capture());
        assertThat(captor.getValue().nombre()).isEqualTo("john.doe");
    }

    @Test
    void loginOtp_throwsAndPublishesAuthFailed_whenInvalidOtp() {
        doThrow(new InvalidOtpException("Código inválido o expirado"))
                .when(otpService).verify("u@escuelaing.edu.co", "999");

        assertThatThrownBy(() -> authService.loginOtp("u@escuelaing.edu.co", "999", "ip"))
                .isInstanceOf(InvalidOtpException.class);

        ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
        verify(eventPublisher).publish(eq("auth.fallido"), captor.capture());
        assertThat(captor.getValue().payload()).containsEntry("motivo", "OTP_INVALIDO");
    }

    @Test
    void loginOtp_publishesMaxIntentosMotivo_whenMessageContainsIntentos() {
        doThrow(new InvalidOtpException("Superaste los intentos máximos"))
                .when(otpService).verify("u@escuelaing.edu.co", "000");

        assertThatThrownBy(() -> authService.loginOtp("u@escuelaing.edu.co", "000", "ip"))
                .isInstanceOf(InvalidOtpException.class);

        ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
        verify(eventPublisher).publish(eq("auth.fallido"), captor.capture());
        assertThat(captor.getValue().payload()).containsEntry("motivo", "MAX_INTENTOS");
    }

    @Test
    void loginOtp_throwsAndPublishesFailedEvent_whenDomainInvalid() {
        doThrow(new InvalidDomainException("bad"))
                .when(domainValidationService).validate("x@bad.com");

        assertThatThrownBy(() -> authService.loginOtp("x@bad.com", "123", "ip"))
                .isInstanceOf(InvalidDomainException.class);

        verify(eventPublisher).publish(eq("auth.fallido"), any());
        verify(otpService, never()).verify(anyString(), anyString());
    }

    // -------------------------------------------------------------------------
    // refresh
    // -------------------------------------------------------------------------

    @Test
    void refresh_returnsNewTokens_onValidRefreshToken() {
        when(refreshTokenService.validate("old-refresh")).thenReturn(userId.toString());
        when(usuarioServiceClient.findById(userId.toString())).thenReturn(usuario);
        when(refreshTokenService.rotate("old-refresh", userId.toString())).thenReturn("new-refresh");
        when(jwtService.generateToken(usuario)).thenReturn("new-access");
        when(jwtService.getExpirationSeconds()).thenReturn(900L);

        TokenResponse response = authService.refresh("old-refresh");

        assertThat(response.accessToken()).isEqualTo("new-access");
        assertThat(response.refreshToken()).isEqualTo("new-refresh");
    }

    @Test
    void refresh_throwsInvalidRefreshTokenException_whenTokenIsNull() {
        when(refreshTokenService.validate("expired")).thenReturn(null);

        assertThatThrownBy(() -> authService.refresh("expired"))
                .isInstanceOf(InvalidRefreshTokenException.class);

        ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
        verify(eventPublisher).publish(eq("auth.fallido"), captor.capture());
        assertThat(captor.getValue().payload()).containsEntry("motivo", "REFRESH_INVALIDO");
    }

    // -------------------------------------------------------------------------
    // logout
    // -------------------------------------------------------------------------

    @Test
    void logout_invalidatesSingleSession_whenNotForced() {
        when(refreshTokenService.validate("token")).thenReturn(userId.toString());

        authService.logout("token", false);

        verify(refreshTokenService).invalidateToken("token", userId.toString());
        verify(refreshTokenService, never()).invalidateAllSessions(any());

        ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
        verify(eventPublisher).publish(eq("sesion.cerrada"), captor.capture());
        assertThat(captor.getValue().payload()).containsEntry("motivo", "LOGOUT_VOLUNTARIO");
    }

    @Test
    void logout_invalidatesAllSessions_whenForced() {
        when(refreshTokenService.validate("token")).thenReturn(userId.toString());
        when(refreshTokenService.invalidateAllSessions(userId.toString())).thenReturn(3L);

        authService.logout("token", true);

        verify(refreshTokenService).invalidateAllSessions(userId.toString());
        verify(refreshTokenService, never()).invalidateToken(any(), any());

        ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
        verify(eventPublisher).publish(eq("sesion.cerrada.forzada"), captor.capture());
        assertThat(captor.getValue().payload()).containsEntry("motivo", "LOGOUT_FORZADO");
        assertThat(captor.getValue().payload()).containsEntry("sesionesInvalidadas", 3L);
    }

    @Test
    void logout_doesNothing_whenTokenUnknown() {
        when(refreshTokenService.validate("unknown")).thenReturn(null);

        authService.logout("unknown", false);

        verify(refreshTokenService, never()).invalidateToken(any(), any());
        verify(refreshTokenService, never()).invalidateAllSessions(any());
        verify(eventPublisher, never()).publish(any(), any());
    }

    // -------------------------------------------------------------------------
    // forceCloseAllSessions
    // -------------------------------------------------------------------------

    @Test
    void forceCloseAllSessions_invalidatesAndPublishesEvent() {
        when(refreshTokenService.invalidateAllSessions(userId.toString())).thenReturn(2L);

        authService.forceCloseAllSessions(userId.toString());

        verify(refreshTokenService).invalidateAllSessions(userId.toString());
        ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
        verify(eventPublisher).publish(eq("sesion.cerrada.forzada"), captor.capture());
        assertThat(captor.getValue().payload()).containsEntry("motivo", "CIERRE_ADMINISTRATIVO");
        assertThat(captor.getValue().payload()).containsEntry("sesionesInvalidadas", 2L);
    }
}