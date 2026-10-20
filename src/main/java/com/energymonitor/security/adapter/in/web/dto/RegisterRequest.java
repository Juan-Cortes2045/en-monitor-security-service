package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of a registration request.
 *
 * <p>Bean validation runs before the controller body, so a malformed request never reaches a
 * use case. The remaining password-strength rules belong to the domain and are enforced by
 * {@code PasswordPolicy} inside the use case.
 *
 * @param email        account address
 * @param password     plain-text candidate, hashed by the password hasher port
 * @param name         first name
 * @param lastName     last name
 * @param profileImage optional profile image location
 */
public record RegisterRequest(
        @NotBlank @Size(max = 255) String email,
        @NotBlank @Size(max = 255) String password,
        @NotBlank @Size(max = 100) String name,
        @NotBlank @Size(max = 100) String lastName,
        @Size(max = 255) String profileImage) {
}
