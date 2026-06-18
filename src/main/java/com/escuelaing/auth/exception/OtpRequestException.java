package com.escuelaing.auth.exception;

/**
 * Solicitud de OTP rechazada por rate limiting (cooldown entre envíos).
 */
public class OtpRequestException extends RuntimeException {

    public OtpRequestException(String message) {
        super(message);
    }
}
