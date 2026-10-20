package com.energymonitor.security.application.exception;

/**
 * Raised when {@code ChangePassword} receives a current password that does not match the
 * stored hash.
 */
public class CurrentPasswordMismatchException extends SecurityApplicationException {

    public CurrentPasswordMismatchException(String message) {
        super(message);
    }
}