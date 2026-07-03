package com.escuelaing.auth.exception;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UsuarioServiceExceptionTest {

    @Test
    void constructorWithMessage_setsMessage() {
        UsuarioServiceException ex = new UsuarioServiceException("service unavailable");

        assertThat(ex.getMessage()).isEqualTo("service unavailable");
        assertThat(ex.getCause()).isNull();
    }

    @Test
    void constructorWithMessageAndCause_setsBoth() {
        Throwable cause = new RuntimeException("connection refused");
        UsuarioServiceException ex = new UsuarioServiceException("service unavailable", cause);

        assertThat(ex.getMessage()).isEqualTo("service unavailable");
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void isRuntimeException() {
        assertThat(new UsuarioServiceException("err"))
                .isInstanceOf(RuntimeException.class);
    }
}