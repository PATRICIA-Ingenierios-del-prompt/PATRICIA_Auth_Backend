package com.escuelaing.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(InvalidTenantException.class)
    public ResponseEntity<ErrorResponse> handleTenant(InvalidTenantException ex) {
        return forbidden(ex.getMessage());
    }

    @ExceptionHandler(InvalidDomainException.class)
    public ResponseEntity<ErrorResponse> handleDomain(InvalidDomainException ex) {
        return forbidden(ex.getMessage());
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ErrorResponse> handleRefreshToken(InvalidRefreshTokenException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                ErrorResponse.builder()
                        .timestamp(Instant.now())
                        .status(401)
                        .error("UNAUTHORIZED")
                        .message(ex.getMessage())
                        .build()
        );
    }

    private ResponseEntity<ErrorResponse> forbidden(String message) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(
                ErrorResponse.builder()
                        .timestamp(Instant.now())
                        .status(403)
                        .error("FORBIDDEN")
                        .message(message)
                        .build()
        );
    }
}