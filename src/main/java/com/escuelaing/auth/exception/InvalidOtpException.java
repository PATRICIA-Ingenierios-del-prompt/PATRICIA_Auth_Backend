package com.escuelaing.auth.exception;

/**
 * Código OTP inválido, expirado o agotado por exceso de intentos.
 */
public class InvalidOtpException extends RuntimeException {

    public InvalidOtpException(String message) {
        super(message);
    }
}
