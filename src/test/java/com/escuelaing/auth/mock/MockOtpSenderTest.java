package com.escuelaing.auth.mock;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatNoException;

class MockOtpSenderTest {

    private final MockOtpSender sender = new MockOtpSender();

    @Test
    void send_doesNotThrow() {
        assertThatNoException().isThrownBy(() ->
                sender.send("user@escuelaing.edu.co", "123456", 5L)
        );
    }

    @Test
    void send_acceptsAnyValidInput() {
        assertThatNoException().isThrownBy(() -> {
            sender.send("admin@mail.escuelaing.edu.co", "000000", 10L);
            sender.send("test@escuelaing.edu.co", "999999", 1L);
        });
    }
}