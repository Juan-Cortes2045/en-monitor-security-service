package com.energymonitor.security.application.exception;

/**
 * Raised when registering or editing an account with an address that another account already
 * uses (INV-003, uniqueness enforced by the persistence layer).
 */
public class EmailAlreadyRegisteredException extends SecurityApplicationException {

    public EmailAlreadyRegisteredException(String message) {
        super(message);
    }
}