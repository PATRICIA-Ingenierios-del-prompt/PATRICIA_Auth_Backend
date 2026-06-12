package com.escuelaing.auth.dto.microsoft;

import com.fasterxml.jackson.annotation.JsonProperty;

public record MicrosoftTokenResponse(

        @JsonProperty("token_type")
        String tokenType,

        String scope,

        @JsonProperty("expires_in")
        Long expiresIn,

        @JsonProperty("access_token")
        String accessToken,

        @JsonProperty("id_token")
        String idToken
) {
}