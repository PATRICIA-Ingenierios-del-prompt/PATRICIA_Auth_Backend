package com.escuelaing.auth.dto.event;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record AuthEvent(
        UUID eventoId,
        Instant timestamp,
        UUID usuarioId,
        String tipo,
        Map<String, Object> payload
) {
}
