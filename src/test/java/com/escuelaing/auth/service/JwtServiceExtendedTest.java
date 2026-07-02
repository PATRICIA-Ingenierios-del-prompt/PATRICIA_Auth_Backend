package com.escuelaing.auth.service;

import com.escuelaing.auth.config.JwtProperties;
import com.escuelaing.auth.dto.usuario.UsuarioResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceExtendedTest {

    private static final String SECRET = "test-secret-key-with-at-least-32-bytes!!";
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        JwtProperties props = new JwtProperties();
        props.setSecret(SECRET);
        props.setExpirationMinutes(15L);
        jwtService = new JwtService(props);
    }

    @Test
    void generateToken_containsExpectedClaims() {
        UUID id = UUID.randomUUID();
        UsuarioResponse usuario = new UsuarioResponse(id, "admin@escuelaing.edu.co", "Admin", List.of("ADMIN"), "ACTIVE");

        String token = jwtService.generateToken(usuario);
        Claims claims = jwtService.validateAndExtract(token);

        assertThat(claims.getSubject()).isEqualTo(id.toString());
        assertThat(claims.get("email", String.class)).isEqualTo("admin@escuelaing.edu.co");
        assertThat(claims.get("roles", List.class)).containsExactly("ADMIN");
    }

    @Test
    void generateToken_expiresAfterConfiguredMinutes() {
        UsuarioResponse usuario = new UsuarioResponse(UUID.randomUUID(), "u@escuelaing.edu.co", "U", List.of(), "ACTIVE");
        String token = jwtService.generateToken(usuario);
        Claims claims = jwtService.validateAndExtract(token);

        long expiresIn = claims.getExpiration().toInstant().getEpochSecond()
                - claims.getIssuedAt().toInstant().getEpochSecond();
        assertThat(expiresIn).isBetween(899L, 901L); // ~15 min
    }

    @Test
    void introspect_returnsValidFalse_forWrongSignature() {
        String fakeToken = Jwts.builder()
                .subject(UUID.randomUUID().toString())
                .claim("email", "u@escuelaing.edu.co")
                .claim("roles", List.of())
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(900)))
                .signWith(Keys.hmacShaKeyFor("different-secret-key-at-least-32-bytes".getBytes(StandardCharsets.UTF_8)))
                .compact();

        Map<String, Object> result = jwtService.introspect(fakeToken);

        assertThat(result.get("valid")).isEqualTo(false);
        assertThat(result.get("reason")).isEqualTo("invalid");
    }

    @Test
    void introspect_returnsValidFalse_forMalformedToken() {
        Map<String, Object> result = jwtService.introspect("not.a.jwt");
        assertThat(result.get("valid")).isEqualTo(false);
    }

    @Test
    void introspect_returnsValidFalse_forExpiredToken() {
        String token = Jwts.builder()
                .subject(UUID.randomUUID().toString())
                .claim("email", "u@escuelaing.edu.co")
                .claim("roles", List.of())
                .issuedAt(Date.from(Instant.now().minusSeconds(120)))
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)))
                .compact();

        Map<String, Object> result = jwtService.introspect(token);

        assertThat(result.get("valid")).isEqualTo(false);
        assertThat(result.get("reason")).isEqualTo("expired");
    }

    @Test
    void introspect_returnsAllFields_forValidToken() {
        UUID id = UUID.randomUUID();
        UsuarioResponse usuario = new UsuarioResponse(id, "u@escuelaing.edu.co", "U", List.of("USER"), "ACTIVE");
        String token = jwtService.generateToken(usuario);

        Map<String, Object> result = jwtService.introspect(token);

        assertThat(result.get("valid")).isEqualTo(true);
        assertThat(result.get("sub")).isEqualTo(id.toString());
        assertThat(result.get("email")).isEqualTo("u@escuelaing.edu.co");
    }

    @Test
    void getExpirationSeconds_returns900_for15Minutes() {
        assertThat(jwtService.getExpirationSeconds()).isEqualTo(900L);
    }

    @Test
    void validateAndExtract_throwsJwtException_forTamperedToken() {
        UsuarioResponse usuario = new UsuarioResponse(UUID.randomUUID(), "u@escuelaing.edu.co", "U", List.of(), "ACTIVE");
        String token = jwtService.generateToken(usuario);
        String tampered = token.substring(0, token.length() - 5) + "XXXXX";

        assertThatThrownBy(() -> jwtService.validateAndExtract(tampered))
                .isInstanceOf(JwtException.class);
    }
}