package com.escuelaing.auth.email;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class ResendOtpSenderTest {

    private static final String RESEND_URL = "https://api.resend.com/emails";
    private static final String FROM_EMAIL = "no-reply@escuelaing.edu.co";
    private static final String API_KEY = "test-resend-api-key";

    private MockRestServiceServer server;
    private ResendOtpSender sender;

    @BeforeEach
    void setUp() {
        RestTemplate restTemplate = new RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();

        RestClient restClient = RestClient.create(restTemplate);
        sender = new ResendOtpSender(restClient);
        ReflectionTestUtils.setField(sender, "fromEmail", FROM_EMAIL);
        ReflectionTestUtils.setField(sender, "apiKey", API_KEY);
    }

    @Test
    void send_postsExpectedRequest_onSuccess() {
        server.expect(requestTo(RESEND_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("Authorization", "Bearer " + API_KEY))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.from").value(FROM_EMAIL))
                .andExpect(jsonPath("$.to[0]").value("user@escuelaing.edu.co"))
                .andExpect(jsonPath("$.subject").value("Tu código de verificación"))
                .andExpect(jsonPath("$.text", org.hamcrest.Matchers.containsString("123456")))
                .andExpect(jsonPath("$.text", org.hamcrest.Matchers.containsString("5")))
                .andRespond(withSuccess());

        assertThatNoException().isThrownBy(() ->
                sender.send("user@escuelaing.edu.co", "123456", 5L)
        );

        server.verify();
    }

    @Test
    void send_throwsIllegalStateException_whenResendRespondsWithServerError() {
        server.expect(requestTo(RESEND_URL))
                .andRespond(withServerError());

        assertThatThrownBy(() -> sender.send("user@escuelaing.edu.co", "123456", 5L))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No se pudo enviar el correo de verificación")
                .hasCauseInstanceOf(org.springframework.web.client.RestClientException.class);

        server.verify();
    }

    @Test
    void send_throwsIllegalStateException_whenResendRespondsWithClientError() {
        server.expect(requestTo(RESEND_URL))
                .andRespond(withBadRequest());

        assertThatThrownBy(() -> sender.send("user@escuelaing.edu.co", "000000", 10L))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No se pudo enviar el correo de verificación");

        server.verify();
    }

    @Test
    void send_doesNotLeakOtpCode_inThrownExceptionMessage() {
        server.expect(requestTo(RESEND_URL))
                .andRespond(withServerError());

        assertThatThrownBy(() -> sender.send("user@escuelaing.edu.co", "999999", 5L))
                .isInstanceOf(IllegalStateException.class)
                .satisfies(ex -> org.assertj.core.api.Assertions.assertThat(ex.getMessage())
                        .doesNotContain("999999"));

        server.verify();
    }

    @Test
    void send_includesExpirationMinutes_inRequestBody() {
        server.expect(requestTo(RESEND_URL))
                .andExpect(jsonPath("$.text", org.hamcrest.Matchers.containsString("Vence en 15 minutos")))
                .andRespond(withSuccess());

        sender.send("another.user@escuelaing.edu.co", "654321", 15L);

        server.verify();
    }
}