package com.escuelaing.auth.mock;

import com.escuelaing.auth.dto.usuario.FindOrCreateUserRequest;
import com.escuelaing.auth.dto.usuario.UsuarioResponse;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

/**
 * Mock temporal del Usuario-Service.
 *
 * Cuando exista el servicio real, reemplazar por Feign:
 *   POST /internal/usuarios/find-or-create
 *   GET  /internal/usuarios/{id}
 * con header X-Internal-Api-Key.
 */
@Component
public class MockUsuarioClient {

    public UsuarioResponse findOrCreate(FindOrCreateUserRequest request) {
        return new UsuarioResponse(
                UUID.randomUUID(),
                request.email(),
                request.nombre(),
                List.of("STUDENT"),
                "ACTIVE"
        );
    }

    /**
     * Simula carga del usuario por ID para el flujo de refresh.
     * En producción llamará a Usuario-Service.
     */
    public UsuarioResponse findById(String userId) {
        return new UsuarioResponse(
                UUID.fromString(userId),
                "usuario@mail.escuelaing.edu.co",
                "Usuario Mock",
                List.of("STUDENT"),
                "ACTIVE"
        );
    }
}