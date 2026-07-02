package com.escuelaing.auth.controller;

import com.escuelaing.auth.config.CorsConfig;
import com.escuelaing.auth.config.SecurityConfig;
import com.escuelaing.auth.security.InternalApiKeyFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(HealthController.class)
@Import({SecurityConfig.class, CorsConfig.class, InternalApiKeyFilter.class})
@ActiveProfiles("test")
class HealthControllerTest {

    @Autowired MockMvc mockMvc;

    @Test
    void health_returns200_withServiceUp() throws Exception {
        // /auth/health está bajo /auth/** → permitAll() en SecurityConfig
        mockMvc.perform(get("/auth/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.service").value("auth-service"))
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.timestamp").isNotEmpty());
    }
}