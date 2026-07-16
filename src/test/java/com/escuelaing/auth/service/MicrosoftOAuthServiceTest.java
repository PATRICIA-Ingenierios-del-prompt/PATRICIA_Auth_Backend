package com.escuelaing.auth.service;

import com.escuelaing.auth.config.AzureProperties;
import com.escuelaing.auth.exception.InvalidDomainException;
import com.escuelaing.auth.exception.InvalidTenantException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/**
 * Pruebas de {@link MicrosoftOAuthService}.
 *
 * <p>El JWKS se sirve desde un {@link HttpServer} local (en vez de mockearse
 * a través del bean {@link RestClient}) porque {@code NimbusJwtDecoder}
 * construye internamente su propio cliente HTTP para resolver
 * {@code jwksUri}, por lo que {@link MockRestServiceServer} no intercepta
 * esa llamada.</p>
 */
class MicrosoftOAuthServiceTest {

    private static final String TENANT_ID = "11111111-2222-3333-4444-555555555555";
    private static final String CLIENT_ID = "test-client-id";
    private static final String TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
    private static final String KEY_ID = "test-key-id";

    private static HttpServer jwksServer;
    private static RSAKey rsaKey;
    private static String jwksUri;

    private MockRestServiceServer server;
    private MicrosoftOAuthService service;
    private AzureProperties azureProperties;

    @BeforeAll
    static void startJwksServer() throws Exception {
        rsaKey = new RSAKeyGenerator(2048).keyID(KEY_ID).generate();
        String jwksJson = new JWKSet(rsaKey.toPublicJWK()).toString();

        jwksServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        jwksServer.createContext("/jwks", exchange -> {
            byte[] bytes = jwksJson.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        jwksServer.start();

        jwksUri = "http://localhost:" + jwksServer.getAddress().getPort() + "/jwks";
    }

    @AfterAll
    static void stopJwksServer() {
        jwksServer.stop(0);
    }

    @BeforeEach
    void setUp() {
        azureProperties = new AzureProperties();
        azureProperties.setClientId(CLIENT_ID);
        azureProperties.setRedirectUri("https://app.escuelaing.edu.co/callback");
        azureProperties.setTokenUrl(TOKEN_URL);
        azureProperties.setJwksUri(jwksUri);

        RestTemplate restTemplate = new RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();
        RestClient restClient = RestClient.create(restTemplate);

        service = new MicrosoftOAuthService(restClient, azureProperties);
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private String buildIdToken(Map<String, Object> claimOverrides) throws Exception {
        Instant now = Instant.now();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject("microsoft-user-id")
                .issuer("https://login.microsoftonline.com/" + TENANT_ID + "/v2.0")
                .audience(CLIENT_ID)
                .claim("tid", TENANT_ID)
                .claim("email", "User@Escuelaing.edu.co")
                .claim("name", "Test User")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)));

        claimOverrides.forEach((key, value) -> {
            if (value == null) {
                builder.claim(key, null);
            } else {
                builder.claim(key, value);
            }
        });

        JWTClaimsSet claimsSet = builder.build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY_ID).build(),
                claimsSet
        );
        signedJWT.sign(new RSASSASigner(rsaKey));

        return signedJWT.serialize();
    }

    private void mockTokenExchange(String idToken) {
        server.expect(requestTo(TOKEN_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_FORM_URLENCODED))
                .andRespond(withSuccess(
                        """
                        {
                          "token_type": "Bearer",
                          "scope": "openid profile email",
                          "expires_in": 3600,
                          "access_token": "fake-access-token",
                          "id_token": "%s"
                        }
                        """.formatted(idToken),
                        MediaType.APPLICATION_JSON
                ));
    }

    // -------------------------------------------------------------------------
    // authenticate - happy path
    // -------------------------------------------------------------------------

    @Test
    void authenticate_returnsUserInfo_onValidToken() throws Exception {
        String idToken = buildIdToken(Map.of());
        mockTokenExchange(idToken);

        Map<String, Object> result = service.authenticate("auth-code", "https://app.escuelaing.edu.co/callback");

        assertThat(result.get("email")).isEqualTo("user@escuelaing.edu.co");
        assertThat(result.get("name")).isEqualTo("Test User");
        assertThat(result.get("microsoftId")).isEqualTo("microsoft-user-id");
        server.verify();
    }

    @Test
    void authenticate_lowercasesEmail() throws Exception {
        String idToken = buildIdToken(Map.of("email", "MixedCase.User@ESCUELAING.edu.co"));
        mockTokenExchange(idToken);

        Map<String, Object> result = service.authenticate("auth-code", null);

        assertThat(result.get("email")).isEqualTo("mixedcase.user@escuelaing.edu.co");
        server.verify();
    }

    @Test
    void authenticate_fallsBackToPreferredUsername_whenEmailClaimMissing() throws Exception {
        // Build a token with no "email" claim but with "preferred_username" instead.
        Instant now = Instant.now();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("microsoft-user-id")
                .issuer("https://login.microsoftonline.com/" + TENANT_ID + "/v2.0")
                .audience(CLIENT_ID)
                .claim("tid", TENANT_ID)
                .claim("preferred_username", "Fallback.User@Escuelaing.edu.co")
                .claim("name", "Fallback User")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY_ID).build(),
                claimsSet
        );
        signedJWT.sign(new RSASSASigner(rsaKey));

        mockTokenExchange(signedJWT.serialize());

        Map<String, Object> result = service.authenticate("auth-code", null);

        assertThat(result.get("email")).isEqualTo("fallback.user@escuelaing.edu.co");
        server.verify();
    }

    @Test
    void authenticate_usesConfiguredRedirectUri_whenNoneProvided() throws Exception {
        String idToken = buildIdToken(Map.of());

        server.expect(requestTo(TOKEN_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().string(org.hamcrest.Matchers.containsString(
                        "redirect_uri=https%3A%2F%2Fapp.escuelaing.edu.co%2Fcallback")))
                .andRespond(withSuccess(
                        """
                        {"token_type":"Bearer","scope":"openid profile email","expires_in":3600,"access_token":"a","id_token":"%s"}
                        """.formatted(idToken),
                        MediaType.APPLICATION_JSON
                ));

        service.authenticate("auth-code", null);

        server.verify();
    }

    // -------------------------------------------------------------------------
    // authenticate - error paths
    // -------------------------------------------------------------------------

    @Test
    void authenticate_throwsInvalidDomainException_whenNoEmailFound() throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("microsoft-user-id")
                .issuer("https://login.microsoftonline.com/" + TENANT_ID + "/v2.0")
                .audience(CLIENT_ID)
                .claim("tid", TENANT_ID)
                .claim("name", "No Email User")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY_ID).build(),
                claimsSet
        );
        signedJWT.sign(new RSASSASigner(rsaKey));

        mockTokenExchange(signedJWT.serialize());

        assertThatThrownBy(() -> service.authenticate("auth-code", null))
                .isInstanceOf(InvalidDomainException.class)
                .hasMessageContaining("No email found");
    }

    @Test
    void authenticate_throwsInvalidTenantException_whenAudienceDoesNotMatchClientId() throws Exception {
        String idToken = buildIdToken(Map.of("aud", "some-other-client-id"));
        mockTokenExchange(idToken);

        assertThatThrownBy(() -> service.authenticate("auth-code", null))
                .isInstanceOf(InvalidTenantException.class)
                .hasMessageContaining("audience");
    }

    @Test
    void authenticate_throwsInvalidTenantException_whenAudienceClaimMissing() throws Exception {
        Map<String, Object> overrides = new java.util.HashMap<>();
        overrides.put("aud", null);
        String idToken = buildIdToken(overrides);
        mockTokenExchange(idToken);

        assertThatThrownBy(() -> service.authenticate("auth-code", null))
                .isInstanceOf(InvalidTenantException.class)
                .hasMessageContaining("Audience claim missing");
    }

    @Test
    void authenticate_throwsInvalidTenantException_whenTenantClaimMissing() throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("microsoft-user-id")
                .issuer("https://login.microsoftonline.com/" + TENANT_ID + "/v2.0")
                .audience(CLIENT_ID)
                .claim("email", "user@escuelaing.edu.co")
                .claim("name", "Test User")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY_ID).build(),
                claimsSet
        );
        signedJWT.sign(new RSASSASigner(rsaKey));

        mockTokenExchange(signedJWT.serialize());

        assertThatThrownBy(() -> service.authenticate("auth-code", null))
                .isInstanceOf(InvalidTenantException.class)
                .hasMessageContaining("Tenant claim missing");
    }

    @Test
    void authenticate_throwsInvalidTenantException_whenIssuerDoesNotMatchTenant() throws Exception {
        String idToken = buildIdToken(Map.of(
                "iss", "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
        ));
        mockTokenExchange(idToken);

        assertThatThrownBy(() -> service.authenticate("auth-code", null))
                .isInstanceOf(InvalidTenantException.class)
                .hasMessageContaining("Invalid issuer");
    }

    @Test
    void authenticate_throwsJwtException_whenTokenIsExpired() throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("microsoft-user-id")
                .issuer("https://login.microsoftonline.com/" + TENANT_ID + "/v2.0")
                .audience(CLIENT_ID)
                .claim("tid", TENANT_ID)
                .claim("email", "user@escuelaing.edu.co")
                .claim("name", "Test User")
                .issueTime(Date.from(now.minusSeconds(600)))
                .expirationTime(Date.from(now.minusSeconds(300)))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY_ID).build(),
                claimsSet
        );
        signedJWT.sign(new RSASSASigner(rsaKey));

        mockTokenExchange(signedJWT.serialize());

        assertThatThrownBy(() -> service.authenticate("auth-code", null))
                .isInstanceOf(org.springframework.security.oauth2.jwt.JwtValidationException.class);
    }

    @Test
    void authenticate_throwsJwtException_whenSignatureIsInvalid() throws Exception {
        RSAKey untrustedKey = new RSAKeyGenerator(2048).keyID(KEY_ID).generate();
        Instant now = Instant.now();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("microsoft-user-id")
                .issuer("https://login.microsoftonline.com/" + TENANT_ID + "/v2.0")
                .audience(CLIENT_ID)
                .claim("tid", TENANT_ID)
                .claim("email", "user@escuelaing.edu.co")
                .claim("name", "Test User")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY_ID).build(),
                claimsSet
        );
        // Firmado con una clave distinta a la publicada en el JWKS -> firma inválida.
        signedJWT.sign(new RSASSASigner(untrustedKey));

        mockTokenExchange(signedJWT.serialize());

        assertThatThrownBy(() -> service.authenticate("auth-code", null))
                .isInstanceOf(org.springframework.security.oauth2.jwt.JwtException.class);
    }
}