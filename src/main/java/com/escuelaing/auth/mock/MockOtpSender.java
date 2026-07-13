package com.escuelaing.auth.mock;

import com.escuelaing.auth.service.OtpSender;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Implementación temporal del envío de OTP.
 *
 * Registra el código en los logs en lugar de enviar un correo. Activa por
 * defecto (perfiles local/test) y también si {@code otp.sender} no se
 * define. En producción se reemplaza por {@link com.escuelaing.auth.email.SesOtpSender}
 * mediante {@code OTP_SENDER=ses}.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "otp.sender", havingValue = "mock", matchIfMissing = true)
public class MockOtpSender implements OtpSender {

    @Override
    public void send(String email, String code, long expirationMinutes) {
        log.info(
                "[MOCK OTP] code for {} is {} (valid for {} min)",
                email, code, expirationMinutes
        );
    }
}