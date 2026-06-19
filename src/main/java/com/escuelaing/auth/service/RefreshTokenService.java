package com.escuelaing.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final String REFRESH_PREFIX    = "refresh:";
    private static final String USER_TOKENS_PREFIX = "user_tokens:";

    private final StringRedisTemplate redisTemplate;

    @Value("${refresh.expiration-days}")
    private long expirationDays;

    /**
     * Crea un refresh token opaco (UUID) y lo guarda en Redis.
     *
     * Estructura:
     *   refresh:<token>  →  <userId>   TTL: 7 días
     *   user_tokens:<userId>  →  SET { <token>, ... }
     */
    public String create(String userId) {

        String token = UUID.randomUUID().toString();
        Duration ttl  = Duration.ofDays(expirationDays);

        // Guardar token → userId
        redisTemplate.opsForValue().set(
                REFRESH_PREFIX + token,
                userId,
                ttl
        );

        // Registrar en el set de tokens del usuario
        redisTemplate.opsForSet().add(
                USER_TOKENS_PREFIX + userId,
                token
        );
        redisTemplate.expire(
                USER_TOKENS_PREFIX + userId,
                ttl
        );

        log.debug("Refresh token created for userId={}", userId);
        return token;
    }

    /**
     * Valida el refresh token y devuelve el userId asociado.
     * Devuelve null si el token no existe o ya expiró.
     */
    public String validate(String token) {
        return redisTemplate.opsForValue()
                .get(REFRESH_PREFIX + token);
    }

    /**
     * Rotación obligatoria:
     * 1. Invalida el token viejo
     * 2. Crea y devuelve un token nuevo para el mismo userId
     */
    public String rotate(String oldToken, String userId) {

        invalidateToken(oldToken, userId);
        return create(userId);
    }

    /**
     * Invalida un único refresh token.
     */
    public void invalidateToken(String token, String userId) {

        redisTemplate.delete(REFRESH_PREFIX + token);
        redisTemplate.opsForSet().remove(
                USER_TOKENS_PREFIX + userId,
                token
        );

        log.debug("Refresh token invalidated for userId={}", userId);
    }

    /**
     * Invalida TODAS las sesiones del usuario.
     * Usado en logout forzado y cierre administrativo.
     */
    public long invalidateAllSessions(String userId) {

        String userTokensKey = USER_TOKENS_PREFIX + userId;
        Set<String> tokens = redisTemplate.opsForSet()
                .members(userTokensKey);

        long invalidated = tokens == null ? 0 : tokens.size();

        if (tokens != null && !tokens.isEmpty()) {
            tokens.forEach(t ->
                    redisTemplate.delete(REFRESH_PREFIX + t)
            );
        }

        redisTemplate.delete(userTokensKey);
        log.info("All sessions invalidated for userId={}, count={}",
                userId, invalidated);
        return invalidated;
    }
}
