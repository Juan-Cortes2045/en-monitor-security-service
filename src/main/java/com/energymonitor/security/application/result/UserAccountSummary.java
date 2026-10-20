package com.energymonitor.security.application.result;

import com.energymonitor.security.domain.model.UserStatus;
import java.time.Instant;
import java.util.List;

/**
 * One row of the user directory an administrator reads.
 *
 * <p>Carries only what the directory shows: no password hash, no profile image and no Google
 * subject.
 *
 * @param idUser        the account
 * @param email         the account address
 * @param name          first name of the person behind the account
 * @param lastName      last name, may be {@code null}
 * @param status        account state
 * @param emailVerified whether the address has been confirmed
 * @param registeredAt  when the account was registered
 * @param lastLoginAt   last successful login, {@code null} when it never logged in
 * @param roles         names of the global roles the account holds, sorted
 */
public record UserAccountSummary(String idUser, String email, String name, String lastName,
                                 UserStatus status, boolean emailVerified, Instant registeredAt,
                                 Instant lastLoginAt, List<String> roles) {

    public UserAccountSummary {
        roles = List.copyOf(roles);
    }
}
