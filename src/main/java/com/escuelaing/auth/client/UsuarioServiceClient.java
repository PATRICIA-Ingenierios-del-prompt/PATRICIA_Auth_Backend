package com.escuelaing.auth.client;

import com.escuelaing.auth.dto.usuario.FindOrCreateUserRequest;
import com.escuelaing.auth.dto.usuario.JuradoCredentialsRequest;
import com.escuelaing.auth.dto.usuario.UsuarioResponse;
import com.escuelaing.auth.exception.InvalidJuradoCredentialsException;
import com.escuelaing.auth.exception.UsuarioServiceException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Cliente HTTP hacia usuario-service (PATRICIA_User_Backend).
 *
 * Contratos consumidos (definidos por usuario-service, NO CAMBIAR):
 *   POST /internal/usuarios/find-or-create
 *   POST /internal/usuarios/jurado/login
 *   GET  /internal/usuarios/{id}
 * autenticados con el header X-Internal-Api-Key.
 *
 * Reemplaza a MockUsuarioClient.
 */
@Slf4j
@Component
public class UsuarioServiceClient {

    private static final String HEADER_API_KEY = "X-Internal-Api-Key";

    private final RestClient restClient;
    private final String baseUrl;
    private final String internalApiKey;

    public UsuarioServiceClient(
            RestClient restClient,
            @Value("${usuario-service.url}") String baseUrl,
            @Value("${security.internal-api-key}") String internalApiKey
    ) {
        this.restClient = restClient;
        this.baseUrl = baseUrl;
        this.internalApiKey = internalApiKey;
    }

    public UsuarioResponse findOrCreate(FindOrCreateUserRequest request) {
        try {
            return restClient.post()
                    .uri(baseUrl + "/internal/usuarios/find-or-create")
                    .header(HEADER_API_KEY, internalApiKey)
                    .body(request)
                    .retrieve()
                    .body(UsuarioResponse.class);
        } catch (RestClientException e) {
            log.error("Error llamando a usuario-service find-or-create para email={}",
                    request.email(), e);
            throw new UsuarioServiceException(
                    "No fue posible comunicarse con usuario-service (find-or-create)", e
            );
        }
    }

    /**
     * Login de jurado (correo + contraseña, sin restricción de dominio).
     * 401 de usuario-service -> credenciales inválidas (correo no registrado
     * o contraseña incorrecta); cualquier otro error -> falla de comunicación.
     */
    public UsuarioResponse loginJurado(String email, String password) {
        try {
            return restClient.post()
                    .uri(baseUrl + "/internal/usuarios/jurado/login")
                    .header(HEADER_API_KEY, internalApiKey)
                    .body(new JuradoCredentialsRequest(email, password))
                    .retrieve()
                    .body(UsuarioResponse.class);
        } catch (HttpClientErrorException.Unauthorized e) {
            throw new InvalidJuradoCredentialsException("Correo o contraseña incorrectos");
        } catch (RestClientException e) {
            log.error("Error llamando a usuario-service jurado/login para email={}", email, e);
            throw new UsuarioServiceException(
                    "No fue posible comunicarse con usuario-service (jurado/login)", e
            );
        }
    }

    public UsuarioResponse findById(String userId) {
        try {
            return restClient.get()
                    .uri(baseUrl + "/internal/usuarios/{id}", userId)
                    .header(HEADER_API_KEY, internalApiKey)
                    .retrieve()
                    .body(UsuarioResponse.class);
        } catch (RestClientException e) {
            log.error("Error llamando a usuario-service findById para userId={}", userId, e);
            throw new UsuarioServiceException(
                    "No fue posible comunicarse con usuario-service (findById)", e
            );
        }
    }
}
