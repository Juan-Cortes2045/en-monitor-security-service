package com.energymonitor.security.application.exception;

/**
 * The email-verification code is wrong or expired, or names no account. The three cases share one
 * exception so the response cannot reveal which addresses are registered.
 */
public class InvalidVerificationCodeException extends SecurityApplicationException {

    public InvalidVerificationCodeException(String message) {
        super(message);
    }
}
