package com.energymonitor.security.application.exception;

/**
 * The deletion code cannot be mailed yet: the mail that carries it is not delivered by the
 * notification service so far, and sending it would leave the message stuck in the outbox.
 */
public class AccountDeletionCodeUnavailableException extends SecurityApplicationException {

    public AccountDeletionCodeUnavailableException(String message) {
        super(message);
    }
}
