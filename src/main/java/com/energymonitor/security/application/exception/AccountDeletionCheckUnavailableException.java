package com.energymonitor.security.application.exception;

/**
 * Whether an account may be deleted could not be asked to energy-monitor-backend: it did not
 * answer in time or answered with an error. The account is not deleted.
 */
public class AccountDeletionCheckUnavailableException extends SecurityApplicationException {

    public AccountDeletionCheckUnavailableException(String message) {
        super(message);
    }

    public AccountDeletionCheckUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
