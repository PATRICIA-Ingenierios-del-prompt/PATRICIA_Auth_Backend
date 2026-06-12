package com.escuelaing.auth.mock;

import com.escuelaing.auth.dto.usuario.FindOrCreateUserRequest;
import com.escuelaing.auth.dto.usuario.UsuarioResponse;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

@Component
public class MockUsuarioClient {

    public UsuarioResponse findOrCreate(
            FindOrCreateUserRequest request
    ) {

        return new UsuarioResponse(
                UUID.randomUUID(),
                request.email(),
                request.nombre(),
                List.of("STUDENT"),
                "ACTIVE"
        );
    }
}