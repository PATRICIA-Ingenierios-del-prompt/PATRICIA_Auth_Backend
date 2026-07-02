package com.escuelaing.auth.exception;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import static org.assertj.core.api.Assertions.assertThat;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleTenant_returnsForbidden() {
        ResponseEntity<ErrorResponse> response =
                handler.handleTenant(new InvalidTenantException("bad tenant"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().error()).isEqualTo("FORBIDDEN");
        assertThat(response.getBody().message()).isEqualTo("bad tenant");
        assertThat(response.getBody().status()).isEqualTo(403);
        assertThat(response.getBody().timestamp()).isNotNull();
    }

    @Test
    void handleDomain_returnsForbidden() {
        ResponseEntity<ErrorResponse> response =
                handler.handleDomain(new InvalidDomainException("domain error"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getBody().error()).isEqualTo("FORBIDDEN");
    }

    @Test
    void handleRefreshToken_returnsUnauthorized() {
        ResponseEntity<ErrorResponse> response =
                handler.handleRefreshToken(new InvalidRefreshTokenException("token expired"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody().status()).isEqualTo(401);
        assertThat(response.getBody().error()).isEqualTo("UNAUTHORIZED");
    }

    @Test
    void handleInvalidOtp_returnsUnauthorized() {
        ResponseEntity<ErrorResponse> response =
                handler.handleInvalidOtp(new InvalidOtpException("bad code"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody().message()).isEqualTo("bad code");
    }

    @Test
    void handleOtpRequest_returnsTooManyRequests() {
        ResponseEntity<ErrorResponse> response =
                handler.handleOtpRequest(new OtpRequestException("wait a bit"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(response.getBody().status()).isEqualTo(429);
        assertThat(response.getBody().error()).isEqualTo("TOO_MANY_REQUESTS");
        assertThat(response.getBody().message()).isEqualTo("wait a bit");
    }

    @Test
    void handleValidation_returnsBadRequest_withFieldMessage() throws Exception {
        BeanPropertyBindingResult bindingResult =
                new BeanPropertyBindingResult(new Object(), "target");
        bindingResult.addError(new FieldError("target", "email", "must not be blank"));

        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(null, bindingResult);

        ResponseEntity<ErrorResponse> response = handler.handleValidation(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().status()).isEqualTo(400);
        assertThat(response.getBody().error()).isEqualTo("BAD_REQUEST");
        assertThat(response.getBody().message()).isEqualTo("must not be blank");
    }

    @Test
    void handleValidation_returnsBadRequest_withFallbackMessage_whenNoFieldError() throws Exception {
        BeanPropertyBindingResult bindingResult =
                new BeanPropertyBindingResult(new Object(), "target");

        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(null, bindingResult);

        ResponseEntity<ErrorResponse> response = handler.handleValidation(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().message()).isEqualTo("Validation failed");
    }
}