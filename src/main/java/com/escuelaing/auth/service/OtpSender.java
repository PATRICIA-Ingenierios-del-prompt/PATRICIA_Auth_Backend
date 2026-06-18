package com.escuelaing.auth.service;

/**
 * Abstracción del canal de envío del código OTP.
 *
 * La implementación por defecto ({@code MockOtpSender}) registra el código en
 * los logs. Cuando exista el servicio de correo real, basta con proveer otra
 * implementación de esta interfaz (ej. SMTP / proveedor de email).
 */
public interface OtpSender {

    void send(String email, String code, long expirationMinutes);
}
