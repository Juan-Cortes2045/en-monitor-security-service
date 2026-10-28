package com.energymonitor.security.adapter.in.web.dto;

import com.energymonitor.security.domain.model.PendingRegistration;
import java.time.Instant;

/**
 * Acknowledgement of a registration: the account does not exist yet, it is created when the
 * code sent to {@code email} is verified.
 *
 * @param email     the address the code was sent to
 * @param expiresAt when the registration is forgotten if it was not verified
 */
public record RegistrationResponse(String email, Instant expiresAt) {

    public static RegistrationResponse from(PendingRegistration registration) {
        return new RegistrationResponse(registration.email().value(), registration.expiresAt());
    }
}
