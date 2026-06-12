package com.escuelaing.auth.service;

import com.escuelaing.auth.dto.response.TokenResponse;
import com.escuelaing.auth.dto.usuario.FindOrCreateUserRequest;
import com.escuelaing.auth.dto.usuario.UsuarioResponse;
import com.escuelaing.auth.mock.MockUsuarioClient;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final MicrosoftOAuthService microsoftOAuthService;

    private final MockUsuarioClient mockUsuarioClient;

    public TokenResponse loginMicrosoft(
            String code
    ) {

        Map<String, Object> microsoftUser =
                microsoftOAuthService.authenticate(
                        code
                );

        UsuarioResponse usuario =
                mockUsuarioClient.findOrCreate(
                        new FindOrCreateUserRequest(
                                (String) microsoftUser.get("email"),
                                (String) microsoftUser.get("name"),
                                (String) microsoftUser.get("microsoftId")
                        )
                );

        return TokenResponse.builder()
                .accessToken("jwt-coming-next")
                .refreshToken("refresh-coming-next")
                .tokenType("Bearer")
                .expiresIn(900L)
                .build();
    }
}