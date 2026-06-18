package com.escuelaing.auth.service;

import com.escuelaing.auth.exception.InvalidOtpException;
import com.escuelaing.auth.exception.OtpRequestException;
import jakarta.annotation.PostConstruct;
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

    /**
     * Hash de relleno usado para comparar en tiempo constante cuando no existe
     * un OTP almacenado. Evita que el camino "sin OTP" sea más rápido (lo que
     * permitiría enumerar correos o guiar un ataque por tiempos).
     */
    private String dummyHash;

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

    @PostConstruct
    void init() {
        // Pre-calcula un hash de relleno con la misma forma que un hash real.
        this.dummyHash = hash("__no_otp__");
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

        // 1. Contabilizar el intento SIEMPRE, exista o no un OTP. Así el
        //    número de intentos no depende de si el correo tiene un código
        //    activo (evita enumeración) y el límite anti fuerza bruta aplica
        //    de forma uniforme.
        Long attempts = redisTemplate.opsForValue().increment(attemptsKey);
        if (attempts != null && attempts == 1L) {
            redisTemplate.expire(
                    attemptsKey,
                    Duration.ofMinutes(expirationMinutes)
            );
        }

        // 2. Calcular el hash del código y comparar en tiempo constante SIEMPRE,
        //    incluso si no hay OTP almacenado (se compara contra un hash de
        //    relleno). El tiempo de respuesta es el mismo en todos los casos,
        //    por lo que un atacante no puede usar los tiempos para guiarse.
        String stored    = redisTemplate.opsForValue().get(otpKey);
        String candidate = hash(code);
        boolean matches  = constantTimeEquals(
                stored != null ? stored : dummyHash,
                candidate
        ) && stored != null;

        // 3. Límite de intentos superado: invalidar y rechazar con el mismo
        //    mensaje genérico para no revelar el estado interno.
        if (attempts == null || attempts > maxAttempts) {
            redisTemplate.delete(otpKey);
            redisTemplate.delete(attemptsKey);
            throw new InvalidOtpException("Código inválido o expirado");
        }

        if (!matches) {
            throw new InvalidOtpException("Código inválido o expirado");
        }

        // 4. Éxito: invalidar (un solo uso).
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
