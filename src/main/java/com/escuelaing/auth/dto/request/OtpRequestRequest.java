package com.escuelaing.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Solicitud de envío de un código OTP al correo institucional.
 */
public record OtpRequestRequest(

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        String email
) {
}
