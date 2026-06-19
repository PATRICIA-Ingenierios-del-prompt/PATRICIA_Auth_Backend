package com.escuelaing.auth.service;

import com.escuelaing.auth.config.JwtProperties;
import com.escuelaing.auth.dto.usuario.UsuarioResponse;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtServiceTest {

    private static final String SECRET = "test-secret-key-with-at-least-32-bytes";

    private final JwtService jwtService = new JwtService(jwtProperties());

    @Test
    void introspectAcceptsValidToken() {
        UsuarioResponse usuario = new UsuarioResponse(
                UUID.randomUUID(),
                "user@escuelaing.edu.co",
                "User",
                List.of("USER"),
                "ACTIVE"
        );

        var result = jwtService.introspect(jwtService.generateToken(usuario));

        assertTrue((Boolean) result.get("valid"));
    }

    @Test
    void introspectRejectsExpiredToken() {
        String token = Jwts.builder()
                .subject(UUID.randomUUID().toString())
                .claim("email", "user@escuelaing.edu.co")
                .claim("roles", List.of("USER"))
                .issuedAt(Date.from(Instant.now().minusSeconds(120)))
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)))
                .compact();

        var result = jwtService.introspect(token);

        assertFalse((Boolean) result.get("valid"));
    }

    @Test
    void validateAndExtractRejectsExpiredToken() {
        String token = Jwts.builder()
                .subject(UUID.randomUUID().toString())
                .issuedAt(Date.from(Instant.now().minusSeconds(120)))
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)))
                .compact();

        assertThrows(JwtException.class, () -> jwtService.validateAndExtract(token));
    }

    private static JwtProperties jwtProperties() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret(SECRET);
        properties.setExpirationMinutes(15L);
        return properties;
    }
}
