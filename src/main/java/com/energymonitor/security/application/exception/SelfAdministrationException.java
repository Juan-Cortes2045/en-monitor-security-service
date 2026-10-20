package com.energymonitor.security.application.exception;

/**
 * Raised when an administrator tries to change their own status or global roles.
 *
 * <p>Refused so an administrator cannot lock themselves out or drop the last administrator by
 * accident; another administrator has to make that change.
 */
public class SelfAdministrationException extends SecurityApplicationException {

    public SelfAdministrationException(String message) {
        super(message);
    }
}
