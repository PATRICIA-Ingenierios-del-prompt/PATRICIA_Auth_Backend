package com.escuelaing.auth.messaging;

import com.escuelaing.auth.dto.event.AuthEvent;
import com.escuelaing.auth.dto.usuario.FindOrCreateUserRequest;
import com.escuelaing.auth.dto.usuario.UsuarioResponse;
import com.escuelaing.auth.client.UsuarioServiceClient;
import com.escuelaing.auth.service.AuthService;
import com.escuelaing.auth.service.DomainValidationService;
import com.escuelaing.auth.service.JwtService;
import com.escuelaing.auth.service.MicrosoftOAuthService;
import com.escuelaing.auth.service.OtpService;
import com.escuelaing.auth.service.RefreshTokenService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthEventPublisherTest {

    @Test
    void publishesSesionIniciadaAfterSuccessfulMicrosoftLogin() {
        MicrosoftOAuthService microsoftOAuthService =
                mock(MicrosoftOAuthService.class);
        UsuarioServiceClient usuarioServiceClient = mock(UsuarioServiceClient.class);
        JwtService jwtService = mock(JwtService.class);
        RefreshTokenService refreshTokenService =
                mock(RefreshTokenService.class);
        OtpService otpService = mock(OtpService.class);
        DomainValidationService domainValidationService =
                mock(DomainValidationService.class);
        AuthEventPublisher eventPublisher =
                mock(AuthEventPublisher.class);

        UUID userId = UUID.randomUUID();
        UsuarioResponse usuario = new UsuarioResponse(
                userId,
                "student@mail.escuelaing.edu.co",
                "Student",
                List.of("STUDENT"),
                "ACTIVE"
        );

        when(microsoftOAuthService.authenticate("code", null))
                .thenReturn(Map.of(
                        "email", usuario.email(),
                        "name", usuario.nombre(),
                        "microsoftId", "microsoft-id"
                ));
        when(usuarioServiceClient.findOrCreate(any(FindOrCreateUserRequest.class)))
                .thenReturn(usuario);
        when(jwtService.generateToken(usuario)).thenReturn("access-token");
        when(jwtService.getExpirationSeconds()).thenReturn(900L);
        when(refreshTokenService.create(userId.toString()))
                .thenReturn("refresh-token");

        AuthService authService = new AuthService(
                microsoftOAuthService,
                usuarioServiceClient,
                jwtService,
                refreshTokenService,
                otpService,
                domainValidationService,
                eventPublisher
        );

        authService.loginMicrosoft("code", null, "127.0.0.1");

        ArgumentCaptor<AuthEvent> eventCaptor =
                ArgumentCaptor.forClass(AuthEvent.class);
        verify(eventPublisher).publish(
                eq("sesion.iniciada"),
                eventCaptor.capture()
        );

        AuthEvent event = eventCaptor.getValue();
        assertNotNull(event.eventoId());
        assertNotNull(event.timestamp());
        assertEquals(userId, event.usuarioId());
        assertEquals("sesion.iniciada", event.tipo());
        assertEquals(usuario.email(), event.payload().get("email"));
        assertEquals("MICROSOFT", event.payload().get("metodo"));
        assertEquals("127.0.0.1", event.payload().get("ip"));
    }
}
