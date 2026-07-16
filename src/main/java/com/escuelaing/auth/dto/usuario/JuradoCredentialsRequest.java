package com.escuelaing.auth.dto.usuario;

/**
 * Cuerpo enviado a POST /internal/usuarios/jurado/login (usuario-service).
 */
public record JuradoCredentialsRequest(
        String email,
        String password
) {
}
