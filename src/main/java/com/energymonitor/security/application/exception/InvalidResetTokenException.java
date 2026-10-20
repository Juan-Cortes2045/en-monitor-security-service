package com.energymonitor.security.application.exception;

/**
 * Raised when a password-reset token is unknown, already used, or expired (INV-009, INV-010).
 */
public class InvalidResetTokenException extends SecurityApplicationException {

    public InvalidResetTokenException(String message) {
        super(message);
    }
}