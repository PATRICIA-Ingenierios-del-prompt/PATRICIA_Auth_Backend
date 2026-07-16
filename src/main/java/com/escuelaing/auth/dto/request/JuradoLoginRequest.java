package com.escuelaing.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Login de jurado: correo + contraseña, sin restricción de dominio
 * institucional (jurados externos). Devuelve JWT + refresh token si las
 * credenciales son válidas.
 */
public record JuradoLoginRequest(

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        String email,

        @NotBlank(message = "Password is required")
        String password
) {
}
