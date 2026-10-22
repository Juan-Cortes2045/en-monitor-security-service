package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of a password change by an authenticated caller.
 *
 * <p>The account is not part of the body: it is read from the validated access token, so a
 * caller cannot change another account's password by asking for it.
 *
 * @param currentPassword the caller's present password, verified by the hasher port
 * @param newPassword     the plain-text replacement, hashed by the password hasher port
 */
public record ChangePasswordRequest(
        @NotBlank @Size(max = 255) String currentPassword,
        @NotBlank @Size(max = 255) String newPassword) {
}
