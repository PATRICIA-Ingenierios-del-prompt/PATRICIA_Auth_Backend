package com.escuelaing.auth.dto.usuario;

import java.util.List;
import java.util.UUID;

public record UsuarioResponse(
        UUID id,
        String email,
        String nombre,
        List<String> roles,
        String estado
) {
}