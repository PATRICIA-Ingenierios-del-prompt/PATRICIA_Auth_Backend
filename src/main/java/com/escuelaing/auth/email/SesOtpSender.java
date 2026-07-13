package com.escuelaing.auth.email;

import com.escuelaing.auth.service.OtpSender;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.ses.SesClient;
import software.amazon.awssdk.services.ses.model.Body;
import software.amazon.awssdk.services.ses.model.Content;
import software.amazon.awssdk.services.ses.model.Destination;
import software.amazon.awssdk.services.ses.model.Message;
import software.amazon.awssdk.services.ses.model.SendEmailRequest;
import software.amazon.awssdk.services.ses.model.SesException;

/**
 * Envío real del OTP por correo usando Amazon SES.
 *
 * Se activa solo con {@code OTP_SENDER=ses}. Las credenciales NO son claves
 * estáticas: {@link SesClient} las resuelve vía el
 * {@code DefaultCredentialsProvider}, que en el pod de EKS toma el rol IAM
 * asociado al ServiceAccount (IRSA) — ver
 * {@code deploy/templates/serviceaccount.yaml} y
 * {@code Ulink_Infra/modules/ses}.
 *
 * Nota de costo: SES cobra ~USD 0.10 por cada 1000 correos (sin costo fijo
 * mensual), y las primeras 62 000 salientes/mes son gratis si el envío se
 * origina en un servicio corriendo en AWS (EC2/EKS/Lambda) — caso de este
 * despliegue. Para un volumen de OTPs de un solo dígito de miles al mes el
 * costo es, en la práctica, cero.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "otp.sender", havingValue = "ses")
public class SesOtpSender implements OtpSender {

    private final SesClient sesClient;

    @Value("${otp.from-email}")
    private String fromEmail;

    public SesOtpSender(SesClient sesClient) {
        this.sesClient = sesClient;
    }

    @Override
    public void send(String email, String code, long expirationMinutes) {
        String subject = "Tu código de verificación";
        String body = """
                Tu código de verificación es: %s

                Vence en %d minutos. Si no solicitaste este código, ignora este mensaje.
                """.formatted(code, expirationMinutes);

        SendEmailRequest request = SendEmailRequest.builder()
                .source(fromEmail)
                .destination(Destination.builder().toAddresses(email).build())
                .message(Message.builder()
                        .subject(Content.builder().data(subject).charset("UTF-8").build())
                        .body(Body.builder()
                                .text(Content.builder().data(body).charset("UTF-8").build())
                                .build())
                        .build())
                .build();

        try {
            sesClient.sendEmail(request);
            log.info("OTP email sent via SES to={}", email);
        } catch (SesException e) {
            // No relanzamos el código/; solo dejamos rastro del fallo de envío.
            // OtpService ya generó y guardó el OTP en Redis antes de llegar aquí,
            // así que un fallo de SES no debe filtrar el código en el mensaje de error.
            log.error("Failed to send OTP email via SES to={}: {}", email, e.awsErrorDetails() != null
                    ? e.awsErrorDetails().errorMessage() : e.getMessage());
            throw new IllegalStateException("No se pudo enviar el correo de verificación", e);
        }
    }
}