package com.energymonitor.security.application.exception;

/**
 * Raised when an operation requires an account that can authenticate but the account is
 * inactive or blocked.
 *
 * <p>A normal application-level condition rather than a server fault, so a later delivery
 * adapter can map it to an appropriate client response.
 */
public class AccountNotActiveException extends SecurityApplicationException {

    public AccountNotActiveException(String message) {
        super(message);
    }
}
