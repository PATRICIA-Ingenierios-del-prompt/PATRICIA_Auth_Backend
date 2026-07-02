package com.escuelaing.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class InternalApiKeyFilterTest {

    @Mock HttpServletRequest request;
    @Mock HttpServletResponse response;
    @Mock FilterChain filterChain;

    InternalApiKeyFilter filter;

    @BeforeEach
    void setUp() {
        filter = new InternalApiKeyFilter();
        ReflectionTestUtils.setField(filter, "internalApiKey", "secret-internal-key");
        SecurityContextHolder.clearContext();
    }

    @Test
    void setsAuthentication_whenValidApiKey_andInternalPath() throws Exception {
        when(request.getRequestURI()).thenReturn("/internal/auth/cerrar-sesion/123");
        when(request.getHeader("X-Internal-Api-Key")).thenReturn("secret-internal-key");

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
                .isEqualTo("internal-service");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doesNotSetAuthentication_whenWrongApiKey() throws Exception {
        when(request.getRequestURI()).thenReturn("/internal/auth/cerrar-sesion/123");
        when(request.getHeader("X-Internal-Api-Key")).thenReturn("wrong-key");

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doesNotSetAuthentication_whenNoApiKeyHeader() throws Exception {
        when(request.getRequestURI()).thenReturn("/internal/auth/cerrar-sesion/123");
        when(request.getHeader("X-Internal-Api-Key")).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void skipsApiKeyCheck_forNonInternalPaths() throws Exception {
        when(request.getRequestURI()).thenReturn("/auth/login/microsoft");

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(request, never()).getHeader("X-Internal-Api-Key");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void setsRoleInternal_whenValidApiKey() throws Exception {
        when(request.getRequestURI()).thenReturn("/internal/auth/cerrar-sesion/1");
        when(request.getHeader("X-Internal-Api-Key")).thenReturn("secret-internal-key");

        filter.doFilterInternal(request, response, filterChain);

        boolean hasRole = SecurityContextHolder.getContext().getAuthentication()
                .getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_INTERNAL"));
        assertThat(hasRole).isTrue();
    }
}