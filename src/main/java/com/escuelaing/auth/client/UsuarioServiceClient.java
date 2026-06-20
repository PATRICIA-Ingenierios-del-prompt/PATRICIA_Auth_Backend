package com.escuelaing.auth.client;

import com.escuelaing.auth.dto.usuario.FindOrCreateUserRequest;
import com.escuelaing.auth.dto.usuario.UsuarioResponse;
import com.escuelaing.auth.exception.UsuarioServiceException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Cliente HTTP hacia usuario-service (PATRICIA_User_Backend).
 *
 * Contratos consumidos (definidos por usuario-service, NO CAMBIAR):
 *   POST /internal/usuarios/find-or-create
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
