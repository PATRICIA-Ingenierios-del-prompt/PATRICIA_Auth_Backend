package com.escuelaing.auth.exception;

public class InvalidDomainException
        extends RuntimeException {

    public InvalidDomainException(String message) {
        super(message);
    }
}