package com.energymonitor.security.application.exception;

/**
 * Raised when a caller address has spent its allowance of password-recovery attempts.
 *
 * <p>Separate from {@link InvalidResetTokenException} on purpose, though both answer the same
 * endpoint. A wrong code is a caller error that should not be retried indefinitely, and a caller
 * exceeding the allowance is a client that should slow down, which HTTP answers as 429 with a
 * {@code Retry-After}. Merging them would force one of those two answers onto the other.
 *
 * <p>The message is fixed rather than reporting how many attempts remain or when the window
 * resets, so the refusal tells an attacker nothing about how close a guess had come.
 */
public class TooManyResetAttemptsException extends SecurityApplicationException {

    public TooManyResetAttemptsException(String message) {
        super(message);
    }
}
