package com.escuelaing.auth.controller;

import com.escuelaing.auth.dto.response.HealthResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
public class HealthController {

    @GetMapping("/auth/health")
    public HealthResponse health() {

        return HealthResponse.builder()
                .service("auth-service")
                .status("UP")
                .timestamp(Instant.now())
                .build();
    }
}