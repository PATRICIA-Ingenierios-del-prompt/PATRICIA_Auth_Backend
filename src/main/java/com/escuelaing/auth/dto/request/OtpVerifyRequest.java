package com.escuelaing.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Verificación del código OTP. Devuelve JWT + refresh token si es válido.
 */
public record OtpVerifyRequest(

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        String email,

        @NotBlank(message = "Code is required")
        @Pattern(regexp = "\\d{4,8}", message = "Code must be numeric")
        String code
) {
}
