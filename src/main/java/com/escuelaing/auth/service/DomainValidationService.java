package com.escuelaing.auth.service;

import com.escuelaing.auth.exception.InvalidDomainException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class DomainValidationService {

    private final List<String> allowedDomains;

    public DomainValidationService(
            @Value("${security.allowed-domains}") String allowedDomains
    ) {
        this.allowedDomains = Arrays.stream(allowedDomains.split(","))
                .map(String::trim)
                .filter(domain -> !domain.isBlank())
                .map(String::toLowerCase)
                .map(domain -> domain.startsWith("@") ? domain : "@" + domain)
                .toList();
    }

    public void validate(String email) {
        if (email == null || !isAllowed(email)) {
            throw new InvalidDomainException(
                    "Only institutional accounts are allowed"
            );
        }
    }

    private boolean isAllowed(String email) {
        String normalizedEmail = email.toLowerCase();
        return allowedDomains.stream()
                .anyMatch(normalizedEmail::endsWith);
    }
}
