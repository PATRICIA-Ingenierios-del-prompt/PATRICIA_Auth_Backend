package com.escuelaing.auth.service;

import com.escuelaing.auth.exception.InvalidOtpException;
import com.escuelaing.auth.exception.OtpRequestException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

/**
 * Gestión del flujo OTP (One-Time Password) como segunda opción de ingreso.
 *
 * Seguridad:
 *   - El código se almacena en Redis HASHEADO (HMAC-SHA256), nunca en claro.
 *   - TTL corto (5 min por defecto) y de un solo uso.
 *   - Límite de intentos de verificación (anti fuerza bruta).
 *   - Cooldown entre solicitudes (anti spam / enumeración).
 *   - Comparación en tiempo constante.
 */
@Slf4j
@Service
public class OtpService {

    private static final String OTP_PREFIX          = "otp:";
    private static final String OTP_ATTEMPTS_PREFIX = "otp:attempts:";
    private static final String OTP_COOLDOWN_PREFIX = "otp:cooldown:";

    private final StringRedisTemplate redisTemplate;
    private final OtpSender otpSender;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${otp.length:6}")
    private int otpLength;

    @Value("${otp.expiration-minutes:5}")
    private long expirationMinutes;

    @Value("${otp.max-attempts:5}")
    private long maxAttempts;

    @Value("${otp.resend-cooldown-seconds:60}")
    private long resendCooldownSeconds;

    @Value("${otp.secret:${jwt.secret}}")
    private String secret;

    public OtpService(StringRedisTemplate redisTemplate, OtpSender otpSender) {
        this.redisTemplate = redisTemplate;
        this.otpSender = otpSender;
    }

    /**
     * Genera un código OTP, lo guarda hasheado en Redis y lo envía.
     * Aplica cooldown para evitar reenvíos abusivos.
     */
    public void requestOtp(String email) {

        String normalized  = email.toLowerCase();
        String cooldownKey = OTP_COOLDOWN_PREFIX + normalized;

        Boolean acquired = redisTemplate.opsForValue().setIfAbsent(
                cooldownKey,
                "1",
                Duration.ofSeconds(resendCooldownSeconds)
        );

        if (Boolean.FALSE.equals(acquired)) {
            throw new OtpRequestException(
                    "Debes esperar antes de solicitar un nuevo código"
            );
        }

        String code = generateCode();

        redisTemplate.opsForValue().set(
                OTP_PREFIX + normalized,
                hash(code),
                Duration.ofMinutes(expirationMinutes)
        );

        // Reinicia el contador de intentos para el nuevo código
        redisTemplate.delete(OTP_ATTEMPTS_PREFIX + normalized);

        otpSender.send(normalized, code, expirationMinutes);

        log.info("OTP issued for email={}", normalized);
    }

    /**
     * Verifica el código. Lanza {@link InvalidOtpException} si es inválido,
     * expiró o se superó el número de intentos. El código se invalida tras
     * un uso exitoso.
     */
    public void verify(String email, String code) {

        String normalized = email.toLowerCase();
        String otpKey      = OTP_PREFIX + normalized;
        String attemptsKey = OTP_ATTEMPTS_PREFIX + normalized;

        String stored = redisTemplate.opsForValue().get(otpKey);

        if (stored == null) {
            throw new InvalidOtpException("Código inválido o expirado");
        }

        Long attempts = redisTemplate.opsForValue().increment(attemptsKey);
        if (attempts != null && attempts == 1L) {
            redisTemplate.expire(
                    attemptsKey,
                    Duration.ofMinutes(expirationMinutes)
            );
        }

        if (attempts != null && attempts > maxAttempts) {
            redisTemplate.delete(otpKey);
            redisTemplate.delete(attemptsKey);
            throw new InvalidOtpException(
                    "Demasiados intentos. Solicita un nuevo código"
            );
        }

        if (!constantTimeEquals(stored, hash(code))) {
            throw new InvalidOtpException("Código inválido o expirado");
        }

        // Éxito: invalidar (un solo uso)
        redisTemplate.delete(otpKey);
        redisTemplate.delete(attemptsKey);

        log.info("OTP verified for email={}", normalized);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private String generateCode() {
        int bound  = (int) Math.pow(10, otpLength);
        int number = secureRandom.nextInt(bound);
        return String.format("%0" + otpLength + "d", number);
    }

    private String hash(String code) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"
            ));
            byte[] digest = mac.doFinal(code.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to hash OTP", e);
        }
    }

    private boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8)
        );
    }
}
