package com.escuelaing.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
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
        return unauthorized(ex.getMessage());
    }

    @ExceptionHandler(InvalidOtpException.class)
    public ResponseEntity<ErrorResponse> handleInvalidOtp(InvalidOtpException ex) {
        return unauthorized(ex.getMessage());
    }

    @ExceptionHandler(OtpRequestException.class)
    public ResponseEntity<ErrorResponse> handleOtpRequest(OtpRequestException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(
                ErrorResponse.builder()
                        .timestamp(Instant.now())
                        .status(429)
                        .error("TOO_MANY_REQUESTS")
                        .message(ex.getMessage())
                        .build()
        );
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldError() != null
                ? ex.getBindingResult().getFieldError().getDefaultMessage()
                : "Validation failed";
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                ErrorResponse.builder()
                        .timestamp(Instant.now())
                        .status(400)
                        .error("BAD_REQUEST")
                        .message(message)
                        .build()
        );
    }

    private ResponseEntity<ErrorResponse> unauthorized(String message) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                ErrorResponse.builder()
                        .timestamp(Instant.now())
                        .status(401)
                        .error("UNAUTHORIZED")
                        .message(message)
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