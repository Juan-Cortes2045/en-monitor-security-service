package com.energymonitor.security.application.exception;

/**
 * The account has a password, and confirms its deletion with it: no deletion code is sent to it.
 */
public class DeletionCodeNotApplicableException extends SecurityApplicationException {

    public DeletionCodeNotApplicableException(String message) {
        super(message);
    }
}
