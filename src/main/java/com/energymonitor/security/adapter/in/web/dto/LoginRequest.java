package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of a login request.
 *
 * @param email    account address
 * @param password plain-text candidate; it is compared through the password hasher port and
 *                 is never stored, logged or echoed
 * @param acceptTerms optional; {@code true} after the client showed the terms and conditions to
 *                    an account that never accepted them (the login answered 428)
 */
public record LoginRequest(
        @NotBlank @Size(max = 255) String email,
        @NotBlank @Size(max = 255) String password,
        Boolean acceptTerms) {

    /** @return whether the terms are accepted with this request */
    public boolean acceptsTerms() {
        return Boolean.TRUE.equals(acceptTerms);
    }
}
