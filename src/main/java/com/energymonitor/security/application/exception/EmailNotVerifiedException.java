package com.energymonitor.security.application.exception;

/**
 * The password was right, but the account has not confirmed its email address, so no session is
 * opened. The client asks for a new verification code and sends the person to enter it.
 */
public class EmailNotVerifiedException extends SecurityApplicationException {

    public EmailNotVerifiedException(String message) {
        super(message);
    }
}
