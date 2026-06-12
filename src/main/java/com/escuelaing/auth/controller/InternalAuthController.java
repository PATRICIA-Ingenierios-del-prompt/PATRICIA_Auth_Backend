package com.escuelaing.auth.controller;

import com.escuelaing.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Endpoints internos protegidos por X-Internal-Api-Key.
 * Usados por otros microservicios (ej. bloqueo administrativo).
 */
@RestController
@RequestMapping("/internal/auth")
@RequiredArgsConstructor
public class InternalAuthController {

    private final AuthService authService;

    @Value("${security.internal-api-key}")
    private String internalApiKey;

    /**
     * Cierre forzado de TODAS las sesiones de un usuario.
     * Casos: bloqueo admin, suspensión bienestar, cierre total.
     */
    @PostMapping("/cerrar-sesion/{userId}")
    public ResponseEntity<Void> cerrarSesion(
            @PathVariable String userId,
            @RequestHeader("X-Internal-Api-Key") String apiKey
    ) {
        if (!internalApiKey.equals(apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        authService.forceCloseAllSessions(userId);
        return ResponseEntity.noContent().build();
    }
}