package com.escuelaing.auth.messaging;

import com.escuelaing.auth.dto.event.AuthEvent;
import com.escuelaing.auth.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class UsuarioEventConsumer {

    private final RefreshTokenService refreshTokenService;

    @RabbitListener(queues = "${messaging.queues.usuarios-suspendidos}")
    public void handleUsuarioSuspendido(AuthEvent event) {
        invalidateSessions(event, "usuario.suspendido");
    }

    @RabbitListener(queues = "${messaging.queues.usuarios-baneados}")
    public void handleUsuarioBaneado(AuthEvent event) {
        invalidateSessions(event, "usuario.baneado");
    }

    private void invalidateSessions(AuthEvent event, String sourceEvent) {
        UUID usuarioId = event.usuarioId();

        if (usuarioId == null) {
            log.warn("Ignoring {} without usuarioId", sourceEvent);
            return;
        }

        long invalidated = refreshTokenService.invalidateAllSessions(
                usuarioId.toString()
        );
        log.info("User event {} invalidated {} sessions for userId={}",
                sourceEvent, invalidated, usuarioId);
    }
}
