package com.escuelaing.auth.service;

import com.escuelaing.auth.exception.InvalidDomainException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DomainValidationServiceTest {

    private final DomainValidationService domainValidationService =
            new DomainValidationService(
                    "@mail.escuelaing.edu.co,@escuelaing.edu.co"
            );

    @Test
    void acceptsAllowedInstitutionalDomains() {
        assertDoesNotThrow(() ->
                domainValidationService.validate("student@mail.escuelaing.edu.co"));
        assertDoesNotThrow(() ->
                domainValidationService.validate("teacher@escuelaing.edu.co"));
    }

    @Test
    void rejectsSimilarButDifferentDomains() {
        assertThrows(InvalidDomainException.class, () ->
                domainValidationService.validate("user@fakeescuelaing.edu.co"));
        assertThrows(InvalidDomainException.class, () ->
                domainValidationService.validate("user@mail.escuelaing.edu.co.attacker.com"));
    }
}
