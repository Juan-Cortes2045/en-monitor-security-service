package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Body of a password reset.
 *
 * <p>The code is accepted here because completing the reset is its entire purpose. It is the
 * clear value, not the stored hash: the use case hashes it before it touches anything, so the
 * value that travels here is the only place this credential exists apart from the delivery that
 * carried it. It is never echoed in a response, and the endpoint that mints it never returns it
 * either.
 *
 * <p>The shape is pinned to six digits rather than left as "some short string". The length is
 * part of the security design and not an implementation detail of the caller: it is what the
 * peppered digest and the rate limit are sized for, so a value of another length is rejected at
 * the edge rather than hashed and looked up. Rejecting it here also saves the caller a round trip
 * that could only have failed.
 *
 * <p>The address is part of the body because the redemption is bound to an account. Without it
 * the only thing a presented code could be compared against is a row found by its own digest,
 * which for a six-digit code is a value an attacker produces by guessing; with it, the code is
 * compared against the pending code of the account that asked for it and against nothing else.
 *
 * @param email       the account the code was requested for
 * @param resetToken  the six-digit code received through the reset channel
 * @param newPassword the plain-text replacement, hashed by the password hasher port
 */
public record ResetPasswordRequest(
        @NotBlank @Email String email,
        @NotBlank
        @Pattern(regexp = "\\d{6}", message = "must be the six-digit code from the recovery email")
        String resetToken,
        @NotBlank @Size(max = 255) String newPassword) {
}
