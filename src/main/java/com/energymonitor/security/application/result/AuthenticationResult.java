package com.energymonitor.security.application.result;

import java.util.Optional;

/**
 * Outcome of an authentication attempt.
 *
 * <p>The authenticated identity is published as an {@link AuthenticatedUser} rather than as
 * the {@code User} aggregate, so a caller can never read the stored password hash through
 * this result.
 *
 * @param status the classification of the attempt
 * @param user   the authenticated identity when {@code status} is
 *               {@link AuthenticationStatus#SUCCESS}, empty otherwise
 */
public record AuthenticationResult(AuthenticationStatus status, Optional<AuthenticatedUser> user) {

    /**
     * @return whether the attempt succeeded
     */
    public boolean isSuccess() {
        return status == AuthenticationStatus.SUCCESS;
    }
}
