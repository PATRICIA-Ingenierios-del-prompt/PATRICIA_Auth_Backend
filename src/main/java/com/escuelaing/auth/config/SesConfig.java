package com.escuelaing.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ses.SesClient;

/**
 * Bean del cliente de SES. Solo se crea cuando OTP_SENDER=ses; en dev/test
 * (mock) ni siquiera se intenta resolver credenciales de AWS, así que el
 * arranque local sigue sin depender de nada de AWS.
 *
 * Las credenciales se resuelven con la cadena por defecto del SDK
 * (DefaultCredentialsProvider), que dentro del pod de EKS usa el rol IAM
 * inyectado vía IRSA (variables AWS_ROLE_ARN / AWS_WEB_IDENTITY_TOKEN_FILE
 * que el webhook de IRSA monta automáticamente en el ServiceAccount con la
 * anotación eks.amazonaws.com/role-arn). No hay claves estáticas en ningún
 * Secret.
 */
@Configuration
@ConditionalOnProperty(name = "otp.sender", havingValue = "ses")
public class SesConfig {

    @Value("${aws.region:us-east-1}")
    private String awsRegion;

    @Bean
    public SesClient sesClient() {
        return SesClient.builder()
                .region(Region.of(awsRegion))
                .build();
    }
}