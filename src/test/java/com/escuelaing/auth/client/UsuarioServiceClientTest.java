package com.escuelaing.auth.client;

import com.escuelaing.auth.dto.usuario.FindOrCreateUserRequest;
import com.escuelaing.auth.dto.usuario.UsuarioResponse;
import com.escuelaing.auth.exception.InvalidJuradoCredentialsException;
import com.escuelaing.auth.exception.UsuarioServiceException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class UsuarioServiceClientTest {

    private static final String BASE_URL = "http://localhost:9090";
    private static final String API_KEY  = "test-api-key";

    private MockRestServiceServer server;
    private UsuarioServiceClient  client;
    private final ObjectMapper    mapper = new ObjectMapper();

    private final UsuarioResponse usuario = new UsuarioResponse(
            UUID.fromString("11111111-1111-1111-1111-111111111111"),
            "user@escuelaing.edu.co",
            "User",
            List.of("USER"),
            "ACTIVE"
    );

    @BeforeEach
    void setUp() {
        // RestTemplate builder compatible con RestClient + MockRestServiceServer
        org.springframework.web.client.RestTemplate restTemplate =
                new org.springframework.web.client.RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();

        RestClient restClient = RestClient.create(restTemplate);
        client = new UsuarioServiceClient(restClient, BASE_URL, API_KEY);
    }

    // -------------------------------------------------------------------------
    // findOrCreate
    // -------------------------------------------------------------------------

    @Test
    void findOrCreate_returnsUsuario_onSuccess() throws Exception {
        server.expect(requestTo(BASE_URL + "/internal/usuarios/find-or-create"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("X-Internal-Api-Key", API_KEY))
                .andRespond(withSuccess(mapper.writeValueAsString(usuario), MediaType.APPLICATION_JSON));

        UsuarioResponse result = client.findOrCreate(
                new FindOrCreateUserRequest("user@escuelaing.edu.co", "User", null)
        );

        assertThat(result.email()).isEqualTo("user@escuelaing.edu.co");
        assertThat(result.id()).isEqualTo(usuario.id());
        server.verify();
    }

    @Test
    void findOrCreate_throwsUsuarioServiceException_on5xxError() {
        server.expect(requestTo(BASE_URL + "/internal/usuarios/find-or-create"))
                .andRespond(withServerError());

        assertThatThrownBy(() -> client.findOrCreate(
                new FindOrCreateUserRequest("user@escuelaing.edu.co", "User", null)
        ))
                .isInstanceOf(UsuarioServiceException.class)
                .hasMessageContaining("find-or-create");
    }

    // -------------------------------------------------------------------------
    // loginJurado
    // -------------------------------------------------------------------------

    @Test
    void loginJurado_returnsUsuario_onSuccess() throws Exception {
        server.expect(requestTo(BASE_URL + "/internal/usuarios/jurado/login"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("X-Internal-Api-Key", API_KEY))
                .andRespond(withSuccess(mapper.writeValueAsString(usuario), MediaType.APPLICATION_JSON));

        UsuarioResponse result = client.loginJurado("user@escuelaing.edu.co", "secret");

        assertThat(result.email()).isEqualTo("user@escuelaing.edu.co");
        server.verify();
    }

    @Test
    void loginJurado_throwsInvalidJuradoCredentialsException_on401() {
        server.expect(requestTo(BASE_URL + "/internal/usuarios/jurado/login"))
                .andRespond(withUnauthorizedRequest());

        assertThatThrownBy(() -> client.loginJurado("jurado@ejemplo.com", "wrong"))
                .isInstanceOf(InvalidJuradoCredentialsException.class)
                .hasMessage("Correo o contraseña incorrectos");
    }

    @Test
    void loginJurado_throwsUsuarioServiceException_on5xxError() {
        server.expect(requestTo(BASE_URL + "/internal/usuarios/jurado/login"))
                .andRespond(withServerError());

        assertThatThrownBy(() -> client.loginJurado("jurado@ejemplo.com", "secret"))
                .isInstanceOf(UsuarioServiceException.class)
                .hasMessageContaining("jurado/login");
    }

    // -------------------------------------------------------------------------
    // findById
    // -------------------------------------------------------------------------

    @Test
    void findById_returnsUsuario_onSuccess() throws Exception {
        String userId = usuario.id().toString();

        server.expect(requestTo(BASE_URL + "/internal/usuarios/" + userId))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("X-Internal-Api-Key", API_KEY))
                .andRespond(withSuccess(mapper.writeValueAsString(usuario), MediaType.APPLICATION_JSON));

        UsuarioResponse result = client.findById(userId);

        assertThat(result.email()).isEqualTo("user@escuelaing.edu.co");
        server.verify();
    }

    @Test
    void findById_throwsUsuarioServiceException_on5xxError() {
        server.expect(requestTo(BASE_URL + "/internal/usuarios/" + usuario.id()))
                .andRespond(withServerError());

        assertThatThrownBy(() -> client.findById(usuario.id().toString()))
                .isInstanceOf(UsuarioServiceException.class)
                .hasMessageContaining("findById");
    }
}