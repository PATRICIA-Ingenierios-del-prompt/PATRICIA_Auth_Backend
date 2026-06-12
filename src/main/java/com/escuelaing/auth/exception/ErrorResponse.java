package com.escuelaing.auth.exception;

import lombok.Builder;

import java.time.Instant;

@Builder
public record ErrorResponse(
        Instant timestamp,
        Integer status,
        String error,
        String message
) {
}