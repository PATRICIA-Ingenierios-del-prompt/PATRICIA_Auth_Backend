package com.escuelaing.auth.exception;

public class InvalidTenantException
        extends RuntimeException {

    public InvalidTenantException(String message) {
        super(message);
    }
}