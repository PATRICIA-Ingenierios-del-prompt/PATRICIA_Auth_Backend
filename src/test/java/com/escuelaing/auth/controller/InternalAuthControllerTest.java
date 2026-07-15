package com.escuelaing.auth.controller;

import com.escuelaing.auth.config.SecurityConfig;
import com.escuelaing.auth.security.InternalApiKeyFilter;
import com.escuelaing.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(InternalAuthController.class)
@Import({SecurityConfig.class, InternalApiKeyFilter.class})
@ActiveProfiles("test")
class InternalAuthControllerTest {

    @Autowired MockMvc mockMvc;
    @MockBean AuthService authService;

    // La API key correcta viene de application-test.yml: test-internal-key

    @Test
    void cerrarSesion_returns204_whenApiKeyIsValid() throws Exception {
        mockMvc.perform(post("/internal/auth/cerrar-sesion/user-123")
                        .header("X-Internal-Api-Key", "test-internal-key"))
                .andExpect(status().isNoContent());

        verify(authService).forceCloseAllSessions("user-123");
    }

    @Test
    void cerrarSesion_returns401_whenApiKeyIsWrong() throws Exception {
        // El filtro no autentica → Spring Security deniega con 403 (FORBIDDEN)
        // porque /internal/** requiere ROLE_INTERNAL
        mockMvc.perform(post("/internal/auth/cerrar-sesion/user-123")
                        .header("X-Internal-Api-Key", "wrong-key"))
                .andExpect(status().isForbidden());

        verify(authService, never()).forceCloseAllSessions(any());
    }

    @Test
    void cerrarSesion_returns403_whenApiKeyIsMissing() throws Exception {
        // Sin header el filtro no autentica → Security deniega con 403
        mockMvc.perform(post("/internal/auth/cerrar-sesion/user-123"))
                .andExpect(status().isForbidden());

        verify(authService, never()).forceCloseAllSessions(any());
    }
}