package com.escuelaing.auth.messaging;

import com.escuelaing.auth.dto.event.AuthEvent;
import com.escuelaing.auth.service.RefreshTokenService;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SuspensionConsumerTest {

    @Test
    void usuarioSuspendidoInvalidatesAllSessions() {
        RefreshTokenService refreshTokenService =
                mock(RefreshTokenService.class);
        UsuarioEventConsumer consumer =
                new UsuarioEventConsumer(refreshTokenService);

        UUID usuarioId = UUID.randomUUID();
        AuthEvent event = new AuthEvent(
                UUID.randomUUID(),
                Instant.now(),
                usuarioId,
                "usuario.suspendido",
                Map.of()
        );

        when(refreshTokenService.invalidateAllSessions(usuarioId.toString()))
                .thenReturn(3L);

        consumer.handleUsuarioSuspendido(event);

        verify(refreshTokenService)
                .invalidateAllSessions(usuarioId.toString());
    }
}
