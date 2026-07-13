package com.escuelaing.auth.email;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import software.amazon.awssdk.services.ses.SesClient;
import software.amazon.awssdk.services.ses.model.SendEmailRequest;
import software.amazon.awssdk.services.ses.model.SendEmailResponse;
import software.amazon.awssdk.services.ses.model.SesException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SesOtpSenderTest {

    @Mock
    SesClient sesClient;

    SesOtpSender sesOtpSender;

    private static final String FROM_EMAIL = "no-reply@test.com";

    @BeforeEach
    void setUp() {
        sesOtpSender = new SesOtpSender(sesClient);
        // Inject @Value field, igual que OtpServiceTest hace con OtpService
        ReflectionTestUtils.setField(sesOtpSender, "fromEmail", FROM_EMAIL);
    }

    @Test
    void send_callsSesClientWithCorrectFromAndDestination() {
        when(sesClient.sendEmail(any(SendEmailRequest.class)))
                .thenReturn(SendEmailResponse.builder().build());

        sesOtpSender.send("student@escuelaing.edu.co", "123456", 5L);

        ArgumentCaptor<SendEmailRequest> captor = ArgumentCaptor.forClass(SendEmailRequest.class);
        verify(sesClient, times(1)).sendEmail(captor.capture());

        SendEmailRequest sent = captor.getValue();
        assertThat(sent.source()).isEqualTo(FROM_EMAIL);
        assertThat(sent.destination().toAddresses()).containsExactly("student@escuelaing.edu.co");
        assertThat(sent.message().subject().data()).isNotBlank();
        assertThat(sent.message().body().text().data()).contains("123456");
    }

    @Test
    void send_includesCodeAndExpirationInBody() {
        when(sesClient.sendEmail(any(SendEmailRequest.class)))
                .thenReturn(SendEmailResponse.builder().build());

        sesOtpSender.send("admin@mail.escuelaing.edu.co", "999999", 10L);

        ArgumentCaptor<SendEmailRequest> captor = ArgumentCaptor.forClass(SendEmailRequest.class);
        verify(sesClient).sendEmail(captor.capture());

        String body = captor.getValue().message().body().text().data();
        assertThat(body).contains("999999");
        assertThat(body).contains("10");
    }

    @Test
    void send_doesNotThrow_whenSesSucceeds() {
        when(sesClient.sendEmail(any(SendEmailRequest.class)))
                .thenReturn(SendEmailResponse.builder().build());

        assertThatNoException().isThrownBy(() ->
                sesOtpSender.send("user@escuelaing.edu.co", "123456", 5L)
        );
    }

    @Test
    void send_wrapsSesExceptionAndDoesNotLeakCode() {
        SesException sesException = (SesException) SesException.builder()
                .message("boom")
                .build();
        when(sesClient.sendEmail(any(SendEmailRequest.class))).thenThrow(sesException);

        assertThatThrownBy(() -> sesOtpSender.send("user@escuelaing.edu.co", "654321", 5L))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageNotContaining("654321")
                .hasCause(sesException);
    }
}