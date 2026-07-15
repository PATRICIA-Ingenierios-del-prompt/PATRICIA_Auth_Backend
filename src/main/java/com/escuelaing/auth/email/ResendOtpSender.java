package com.escuelaing.auth.email;

import com.escuelaing.auth.service.OtpSender;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.List;
import java.util.Map;

/**
 * Envío real del OTP por correo usando la API HTTP de Resend
 * (https://resend.com/docs/api-reference/emails/send-email).
 *
 * Se activa solo con {@code OTP_SENDER=resend}. A diferencia del SesOtpSender
 * que reemplaza (removido: ya no se usa Amazon SES), la autenticación NO es
 * vía IRSA/rol IAM sino un API key estático de Resend, inyectado por
 * ExternalSecrets como {@code RESEND_API_KEY} (ver
 * deploy/templates/externalsecret.yaml). El ServiceAccount de este pod ya no
 * necesita ninguna anotación eks.amazonaws.com/role-arn para el envío de
 * correo.
 *
 * Reusa el bean {@link RestClient} genérico ya definido en
 * {@code HttpClientConfig} (el mismo que usa UsuarioServiceClient), en vez de
 * agregar un SDK nuevo al pom.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "otp.sender", havingValue = "resend")
public class ResendOtpSender implements OtpSender {

    private static final String RESEND_API_URL = "https://api.resend.com/emails";

    private final RestClient restClient;

    @Value("${otp.from-email}")
    private String fromEmail;

    @Value("${resend.api-key}")
    private String apiKey;

    public ResendOtpSender(RestClient restClient) {
        this.restClient = restClient;
    }

    @Override
    public void send(String email, String code, long expirationMinutes) {
        String subject = "Tu código de verificación";
        String body = """
                Tu código de verificación es: %s

                Vence en %d minutos. Si no solicitaste este código, ignora este mensaje.
                """.formatted(code, expirationMinutes);

        Map<String, Object> payload = Map.of(
                "from", fromEmail,
                "to", List.of(email),
                "subject", subject,
                "text", body
        );

        try {
            restClient.post()
                    .uri(RESEND_API_URL)
                    .header("Authorization", "Bearer " + apiKey)
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(payload)
                    .retrieve()
                    .toBodilessEntity();
            log.info("OTP email sent via Resend to={}", email);
        } catch (RestClientException e) {
            // No relanzamos el código; solo dejamos rastro del fallo de envío.
            // OtpService ya generó y guardó el OTP en Redis antes de llegar aquí,
            // así que un fallo de Resend no debe filtrar el código en el mensaje de error.
            log.error("Failed to send OTP email via Resend to={}: {}", email, e.getMessage());
            throw new IllegalStateException("No se pudo enviar el correo de verificación", e);
        }
    }
}
