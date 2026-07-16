package com.escuelaing.auth.exception;

/**
 * Correo/contraseña de jurado inválidos (no registrados en usuario-service
 * o contraseña incorrecta). Se traduce a HTTP 401.
 */
public class InvalidJuradoCredentialsException extends RuntimeException {

    public InvalidJuradoCredentialsException(String message) {
        super(message);
    }
}
