package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Body of {@code POST /api/v1/auth/account/delete}: exactly one of the two confirmations.
 *
 * @param password the current password, for an account that has one
 * @param code     the six-digit code from {@code POST /api/v1/auth/account/delete/code}, for an
 *                 account created with Google
 */
public record DeleteAccountRequest(@Size(max = 255) String password,
                                   @Pattern(regexp = "\\d{6}") String code) {

    /** One confirmation, never both and never none. */
    @AssertTrue(message = "send either password or code")
    public boolean isOneConfirmation() {
        return isPresent(password) != isPresent(code);
    }

    private static boolean isPresent(String value) {
        return value != null && !value.isBlank();
    }
}
