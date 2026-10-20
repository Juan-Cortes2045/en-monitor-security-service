package com.energymonitor.security.application.exception;

/**
 * Raised when an operation requires a {@code SystemRole} (or an active role assignment) that
 * does not exist or is no longer active.
 */
public class RoleNotFoundException extends SecurityApplicationException {

    public RoleNotFoundException(String message) {
        super(message);
    }
}