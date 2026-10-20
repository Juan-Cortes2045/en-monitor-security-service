package com.energymonitor.security.application.exception;

/**
 * Raised when an operation requires a {@code UserSession} that does not exist or is no longer
 * active.
 */
public class SessionNotFoundException extends SecurityApplicationException {

    public SessionNotFoundException(String message) {
        super(message);
    }
}