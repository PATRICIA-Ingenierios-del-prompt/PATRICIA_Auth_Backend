package com.escuelaing.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

public record MicrosoftCodeRequest(

        @NotBlank(message = "Code is required")
        String code,

        String redirectUri
) {
}