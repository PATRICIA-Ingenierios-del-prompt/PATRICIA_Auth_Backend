package com.escuelaing.auth.exception;

/**
 * Error al comunicarse con usuario-service (timeout, conexión rechazada,
 * respuesta 5xx, o cualquier fallo inesperado del cliente HTTP).
 */
public class UsuarioServiceException extends RuntimeException {

    public UsuarioServiceException(String message, Throwable cause) {
        super(message, cause);
    }

    public UsuarioServiceException(String message) {
        super(message);
    }
}
