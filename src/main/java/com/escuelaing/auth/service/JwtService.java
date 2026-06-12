package com.escuelaing.auth.service;

import com.escuelaing.auth.config.JwtProperties;
import com.escuelaing.auth.dto.usuario.UsuarioResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties jwtProperties;

    /**
     * Genera JWT HS256.
     *
     * Claims:
     *   sub   → UUID del usuario
     *   email → correo institucional
     *   roles → lista de roles
     *   iat   → timestamp emisión
     *   exp   → timestamp expiración (15 min por defecto)
     *
     * NO se incluye nombre: evita tokens obsoletos si cambia el perfil.
     */
    public String generateToken(UsuarioResponse usuario) {

        Instant now        = Instant.now();
        Instant expiration = now.plusSeconds(getExpirationSeconds());

        return Jwts.builder()
                .subject(usuario.id().toString())
                .claim("email", usuario.email())
                .claim("roles", usuario.roles())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Valida el token y extrae los claims.
     * Lanza JwtException si la firma es inválida o el token expiró.
     */
    public Claims validateAndExtract(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Introspección para el endpoint /auth/validate.
     * Nunca lanza excepción: devuelve { valid: false } si algo falla.
     */
    public Map<String, Object> introspect(String token) {
        try {
            Claims claims = validateAndExtract(token);
            return Map.of(
                    "valid", true,
                    "sub",   claims.getSubject(),
                    "email", claims.get("email", String.class),
                    "roles", claims.get("roles", List.class)
            );
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Token introspection failed: {}", e.getMessage());
            return Map.of("valid", false);
        }
    }

    /**
     * Expiración en segundos (para el campo expiresIn del response).
     */
    public long getExpirationSeconds() {
        return jwtProperties.getExpirationMinutes() * 60;
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtProperties.getSecret()
                .getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}