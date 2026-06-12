package com.escuelaing.auth.controller;

import com.escuelaing.auth.dto.request.MicrosoftCodeRequest;
import com.escuelaing.auth.dto.response.TokenResponse;
import com.escuelaing.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login/microsoft")
    public TokenResponse loginMicrosoft(
            @Valid
            @RequestBody
            MicrosoftCodeRequest request
    ) {

        return authService.loginMicrosoft(
                request.code()
        );
    }
}