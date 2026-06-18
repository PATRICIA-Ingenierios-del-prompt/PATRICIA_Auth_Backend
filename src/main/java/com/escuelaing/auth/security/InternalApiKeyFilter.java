package com.escuelaing.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

/**
 * Autentica las peticiones a {@code /internal/**} mediante el header
 * {@code X-Internal-Api-Key}.
 *
 * Sin este filtro la regla {@code .authenticated()} de la cadena de seguridad
 * nunca se satisface (no hay mecanismo de autenticación), dejando los endpoints
 * internos inalcanzables. Con él, solo las peticiones con la API key correcta
 * obtienen un {@code Authentication} con el rol {@code INTERNAL}.
 */
@Component
public class InternalApiKeyFilter extends OncePerRequestFilter {

    private static final String INTERNAL_PATH_PREFIX = "/internal/";
    private static final String HEADER = "X-Internal-Api-Key";

    @Value("${security.internal-api-key}")
    private String internalApiKey;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        if (request.getRequestURI().startsWith(INTERNAL_PATH_PREFIX)) {

            String apiKey = request.getHeader(HEADER);

            if (apiKey != null && constantTimeEquals(apiKey, internalApiKey)) {
                var authentication = new UsernamePasswordAuthenticationToken(
                        "internal-service",
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_INTERNAL"))
                );
                SecurityContextHolder.getContext()
                        .setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8)
        );
    }
}
