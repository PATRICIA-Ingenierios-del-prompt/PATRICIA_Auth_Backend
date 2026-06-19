package com.escuelaing.auth.service;

import com.escuelaing.auth.config.AzureProperties;
import com.escuelaing.auth.dto.microsoft.MicrosoftTokenResponse;
import com.escuelaing.auth.exception.InvalidDomainException;
import com.escuelaing.auth.exception.InvalidTenantException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class MicrosoftOAuthService {

    private final RestClient restClient;
    private final AzureProperties azureProperties;

    public Map<String, Object> authenticate(String authorizationCode) {

        log.info("Microsoft authentication started");

        MicrosoftTokenResponse response =
                exchangeCodeForTokens(authorizationCode);

        Jwt jwt = validateMicrosoftIdToken(response.idToken());

        String email = extractEmail(jwt);

        log.info("Microsoft email: {}", email);
        log.info("Microsoft tenant: {}",
                jwt.getClaimAsString("tid"));

        return Map.of(
                "email", email,
                "name", jwt.getClaimAsString("name"),
                "microsoftId", jwt.getSubject()
        );
    }

    private MicrosoftTokenResponse exchangeCodeForTokens(String code) {

        LinkedMultiValueMap<String, String> body =
                new LinkedMultiValueMap<>();

        body.add("client_id",
                azureProperties.getClientId());
        body.add("client_secret",
                azureProperties.getClientSecret());
        body.add("grant_type",
                "authorization_code");
        body.add("code", code);
        body.add("redirect_uri",
                azureProperties.getRedirectUri());
        body.add("scope",
                "openid profile email");

        return restClient.post()
                .uri(azureProperties.getTokenUrl())
                .contentType(
                        org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED
                )
                .body(body)
                .retrieve()
                .body(MicrosoftTokenResponse.class);
    }

    private Jwt validateMicrosoftIdToken(String idToken) {

        NimbusJwtDecoder decoder =
                NimbusJwtDecoder.withJwkSetUri(
                        azureProperties.getJwksUri()
                ).build();
        decoder.setJwtValidator(JwtValidators.createDefault());

        Jwt jwt = decoder.decode(idToken);

        validateAudience(jwt);
        validateIssuerMatchesTokenTenant(jwt);

        return jwt;
    }

    private void validateAudience(Jwt jwt) {

        if (jwt.getAudience() == null
                || jwt.getAudience().isEmpty()) {

            throw new InvalidTenantException(
                    "Audience claim missing"
            );
        }

        String aud = jwt.getAudience().get(0);

        if (!azureProperties.getClientId().equals(aud)) {
            throw new InvalidTenantException(
                    "Invalid audience"
            );
        }
    }

    private void validateIssuerMatchesTokenTenant(Jwt jwt) {

        String tid = jwt.getClaimAsString("tid");

        if (tid == null || tid.isBlank()) {
            throw new InvalidTenantException(
                    "Tenant claim missing"
            );
        }

        if (jwt.getIssuer() == null) {
            throw new InvalidTenantException(
                    "Issuer claim missing"
            );
        }

        String expectedIssuer =
                "https://login.microsoftonline.com/"
                        + tid
                        + "/v2.0";

        String issuer = jwt.getIssuer().toString();

        if (!expectedIssuer.equals(issuer)) {
            throw new InvalidTenantException(
                    "Invalid issuer"
            );
        }
    }

    private String extractEmail(Jwt jwt) {

        String email = jwt.getClaimAsString("email");

        if (email == null) {
            email = jwt.getClaimAsString(
                    "preferred_username"
            );
        }

        if (email == null) {
            throw new InvalidDomainException(
                    "No email found in Microsoft account"
            );
        }

        return email.toLowerCase();
    }
}
