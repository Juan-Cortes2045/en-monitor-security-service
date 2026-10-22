package com.energymonitor.security.application.exception;

/**
 * Raised when a candidate password does not satisfy the configured {@code PasswordPolicy}
 * (INV-015, INV-016).
 */
public class PasswordPolicyViolationException extends SecurityApplicationException {

    public PasswordPolicyViolationException(String message) {
        super(message);
    }
}