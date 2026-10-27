package com.energymonitor.security.application.exception;

/**
 * The account signs in with Google: it has no password the person knows, so there is none to
 * change.
 */
public class PasswordManagedByGoogleException extends SecurityApplicationException {

    public PasswordManagedByGoogleException(String message) {
        super(message);
    }
}
