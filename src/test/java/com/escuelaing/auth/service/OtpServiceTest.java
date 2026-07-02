package com.escuelaing.auth.service;

import com.escuelaing.auth.exception.InvalidOtpException;
import com.escuelaing.auth.exception.OtpRequestException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

    @Mock StringRedisTemplate redisTemplate;
    @Mock ValueOperations<String, String> valueOps;
    @Mock OtpSender otpSender;

    OtpService otpService;

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        otpService = new OtpService(redisTemplate, otpSender);

        // Inject @Value fields
        ReflectionTestUtils.setField(otpService, "otpLength", 6);
        ReflectionTestUtils.setField(otpService, "expirationMinutes", 5L);
        ReflectionTestUtils.setField(otpService, "maxAttempts", 5L);
        ReflectionTestUtils.setField(otpService, "resendCooldownSeconds", 60L);
        ReflectionTestUtils.setField(otpService, "secret", "test-secret-32-bytes-long-padding!");

        // @PostConstruct
        otpService.init();
    }

    // -------------------------------------------------------------------------
    // requestOtp
    // -------------------------------------------------------------------------

    @Test
    void requestOtp_storesHashedCodeAndSendsOtp() {
        when(valueOps.setIfAbsent(anyString(), anyString(), any(Duration.class))).thenReturn(true);

        otpService.requestOtp("user@escuelaing.edu.co");

        verify(valueOps).set(eq("otp:user@escuelaing.edu.co"), anyString(), eq(Duration.ofMinutes(5)));
        verify(otpSender).send(eq("user@escuelaing.edu.co"), anyString(), eq(5L));
        verify(redisTemplate).delete("otp:attempts:user@escuelaing.edu.co");
    }

    @Test
    void requestOtp_normalizesEmailToLowercase() {
        when(valueOps.setIfAbsent(anyString(), anyString(), any(Duration.class))).thenReturn(true);

        otpService.requestOtp("User@Escuelaing.Edu.Co");

        verify(valueOps).set(eq("otp:user@escuelaing.edu.co"), anyString(), any());
    }

    @Test
    void requestOtp_throwsOtpRequestException_whenCooldownActive() {
        when(valueOps.setIfAbsent(anyString(), anyString(), any(Duration.class))).thenReturn(false);

        assertThatThrownBy(() -> otpService.requestOtp("user@escuelaing.edu.co"))
                .isInstanceOf(OtpRequestException.class)
                .hasMessageContaining("esperar");

        verify(otpSender, never()).send(any(), any(), anyLong());
    }

    // -------------------------------------------------------------------------
    // verify
    // -------------------------------------------------------------------------

    @Test
    void verify_throwsInvalidOtpException_whenCodeIsWrong() {
        when(valueOps.increment(anyString())).thenReturn(1L);
        when(valueOps.get("otp:user@escuelaing.edu.co")).thenReturn("some-stored-hash");

        assertThatThrownBy(() -> otpService.verify("user@escuelaing.edu.co", "000000"))
                .isInstanceOf(InvalidOtpException.class);
    }

    @Test
    void verify_throwsInvalidOtpException_whenNoOtpStored() {
        when(valueOps.increment(anyString())).thenReturn(1L);
        when(valueOps.get("otp:user@escuelaing.edu.co")).thenReturn(null);

        assertThatThrownBy(() -> otpService.verify("user@escuelaing.edu.co", "123456"))
                .isInstanceOf(InvalidOtpException.class);
    }

    @Test
    void verify_throwsInvalidOtpException_whenAttemptsExceeded() {
        when(valueOps.increment(anyString())).thenReturn(6L); // > maxAttempts (5)
        when(valueOps.get(anyString())).thenReturn("any-hash");

        assertThatThrownBy(() -> otpService.verify("user@escuelaing.edu.co", "123456"))
                .isInstanceOf(InvalidOtpException.class);

        verify(redisTemplate).delete("otp:user@escuelaing.edu.co");
        verify(redisTemplate).delete("otp:attempts:user@escuelaing.edu.co");
    }

    @Test
    void verify_throwsInvalidOtpException_whenAttemptsIsNull() {
        when(valueOps.increment(anyString())).thenReturn(null);
        when(valueOps.get(anyString())).thenReturn("any-hash");

        assertThatThrownBy(() -> otpService.verify("user@escuelaing.edu.co", "123456"))
                .isInstanceOf(InvalidOtpException.class);
    }

    @Test
    void verify_setsExpirationOnFirstAttempt() {
        when(valueOps.increment("otp:attempts:user@escuelaing.edu.co")).thenReturn(1L);
        when(valueOps.get("otp:user@escuelaing.edu.co")).thenReturn("any-hash");

        try {
            otpService.verify("user@escuelaing.edu.co", "bad");
        } catch (InvalidOtpException ignored) {}

        verify(redisTemplate).expire("otp:attempts:user@escuelaing.edu.co", Duration.ofMinutes(5));
    }

    @Test
    void verify_doesNotSetExpiration_onSubsequentAttempts() {
        when(valueOps.increment("otp:attempts:user@escuelaing.edu.co")).thenReturn(2L);
        when(valueOps.get("otp:user@escuelaing.edu.co")).thenReturn("any-hash");

        try {
            otpService.verify("user@escuelaing.edu.co", "bad");
        } catch (InvalidOtpException ignored) {}

        verify(redisTemplate, never()).expire(anyString(), any(Duration.class));
    }
}