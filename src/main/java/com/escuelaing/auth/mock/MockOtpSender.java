package com.escuelaing.auth.mock;

import com.escuelaing.auth.service.OtpSender;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Implementación temporal del envío de OTP.
 *
 * Registra el código en los logs en lugar de enviar un correo. Cuando exista el
 * servicio de correo real, reemplazar por una implementación SMTP de
 * {@link OtpSender}.
 */
@Slf4j
@Component
public class MockOtpSender implements OtpSender {

    @Override
    public void send(String email, String code, long expirationMinutes) {
        log.info(
                "[MOCK OTP] code for {} is {} (valid for {} min)",
                email, code, expirationMinutes
        );
    }
}
