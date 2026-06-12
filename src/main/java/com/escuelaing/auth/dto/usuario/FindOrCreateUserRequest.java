package com.escuelaing.auth.dto.usuario;

public record FindOrCreateUserRequest(
        String email,
        String nombre,
        String microsoftId
) {
}