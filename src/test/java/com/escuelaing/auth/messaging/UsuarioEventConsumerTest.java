package com.escuelaing.auth.messaging;

import com.escuelaing.auth.dto.event.AuthEvent;
import com.escuelaing.auth.service.RefreshTokenService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UsuarioEventConsumerTest {

    @Mock RefreshTokenService refreshTokenService;
    @InjectMocks UsuarioEventConsumer consumer;

    @Test
    void handleUsuarioBaneado_invalidatesAllSessions() {
        UUID userId = UUID.randomUUID();
        AuthEvent event = new AuthEvent(UUID.randomUUID(), Instant.now(), userId, "usuario.baneado", Map.of());
        when(refreshTokenService.invalidateAllSessions(userId.toString())).thenReturn(2L);

        consumer.handleUsuarioBaneado(event);

        verify(refreshTokenService).invalidateAllSessions(userId.toString());
    }

    @Test
    void handleUsuarioSuspendido_ignoresEvent_whenUsuarioIdIsNull() {
        AuthEvent event = new AuthEvent(UUID.randomUUID(), Instant.now(), null, "usuario.suspendido", Map.of());

        consumer.handleUsuarioSuspendido(event);

        verify(refreshTokenService, never()).invalidateAllSessions(any());
    }

    @Test
    void handleUsuarioBaneado_ignoresEvent_whenUsuarioIdIsNull() {
        AuthEvent event = new AuthEvent(UUID.randomUUID(), Instant.now(), null, "usuario.baneado", Map.of());

        consumer.handleUsuarioBaneado(event);

        verify(refreshTokenService, never()).invalidateAllSessions(any());
    }
}