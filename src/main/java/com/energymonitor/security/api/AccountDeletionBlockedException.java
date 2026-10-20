package com.energymonitor.security.api;

/**
 * Thrown by a listener of {@link AccountDeleted} to refuse the deletion, which rolls it back. The
 * message is shown to the user, so it must be readable. Mapped to {@code 409} by the web layer.
 */
public class AccountDeletionBlockedException extends RuntimeException {

    public AccountDeletionBlockedException(String message) {
        super(message);
    }
}
