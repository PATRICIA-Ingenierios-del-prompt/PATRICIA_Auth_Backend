package com.escuelaing.auth.service;

import com.escuelaing.auth.config.AzureProperties;
import com.escuelaing.auth.dto.microsoft.MicrosoftTokenResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class MicrosoftOAuthServiceTest {

    private MockRestServiceServer server;
    private MicrosoftOAuthService microsoftOAuthService;
    private final ObjectMapper mapper = new ObjectMapper();

    private static final String TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
    private static final String JWKS_URI  = "https://login.microsoftonline.com/common/discovery/v2.0/keys";
    private static final String CLIENT_ID = "test-client-id";

    @BeforeEach
    void setUp() {
        RestTemplate restTemplate = new RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();
        RestClient restClient = RestClient.create(restTemplate);

        AzureProperties props = new AzureProperties();
        props.setClientId(CLIENT_ID);
        props.setClientSecret("test-secret");
        props.setRedirectUri("http://localhost/callback");
        props.setTokenUrl(TOKEN_URL);
        props.setJwksUri(JWKS_URI);

        microsoftOAuthService = new MicrosoftOAuthService(restClient, props);
    }

    @Test
    void authenticate_throwsException_whenTokenEndpointReturnsError() throws Exception {
        // Simula que el endpoint de Microsoft devuelve 400
        server.expect(requestTo(TOKEN_URL))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andRespond(withBadRequest());

        assertThatThrownBy(() -> microsoftOAuthService.authenticate("bad-code"))
                .isInstanceOf(Exception.class);

        server.verify();
    }

    @Test
    void authenticate_throwsException_whenTokenEndpointReturns5xx() throws Exception {
        server.expect(requestTo(TOKEN_URL))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andRespond(withServerError());

        assertThatThrownBy(() -> microsoftOAuthService.authenticate("code"))
                .isInstanceOf(Exception.class);

        server.verify();
    }

    @Test
    void authenticate_throwsException_whenIdTokenIsInvalid() throws Exception {
        // El token endpoint responde OK pero el id_token es basura
        MicrosoftTokenResponse fakeResponse = new MicrosoftTokenResponse(
                "Bearer", "openid", 3600L, "access-token", "not.a.valid.jwt"
        );

        server.expect(requestTo(TOKEN_URL))
                .andRespond(withSuccess(
                        mapper.writeValueAsString(fakeResponse),
                        MediaType.APPLICATION_JSON
                ));

        // El decoder de Nimbus lanza excepción con un JWT inválido
        assertThatThrownBy(() -> microsoftOAuthService.authenticate("code"))
                .isInstanceOf(Exception.class);

        server.verify();
    }
}