package com.energymonitor.security.application.exception;

/** The domain of the address does not exist or cannot receive mail, so no account is created. */
public class UndeliverableEmailException extends SecurityApplicationException {

    public UndeliverableEmailException(String message) {
        super(message);
    }
}
