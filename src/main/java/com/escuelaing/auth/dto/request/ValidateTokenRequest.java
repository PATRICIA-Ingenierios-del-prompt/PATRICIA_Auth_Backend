package com.escuelaing.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

public record ValidateTokenRequest(
        @NotBlank String token
) {}