package com.energymonitor.security.application.exception;

/**
 * Raised when an operation requires a {@code User} (or, by extension, its {@code Person})
 * that does not exist or is no longer active.
 */
public class UserNotFoundException extends SecurityApplicationException {

    public UserNotFoundException(String message) {
        super(message);
    }
}