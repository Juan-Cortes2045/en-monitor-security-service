package com.energymonitor.security.application.result;

/**
 * Classification of an authentication attempt.
 */
public enum AuthenticationStatus {

    /** The credentials matched an active account. */
    SUCCESS,

    /** No account exists for the supplied address. */
    USER_NOT_FOUND,

    /** The account exists but the password did not match. */
    INVALID_CREDENTIALS,

    /** The account exists but is blocked. */
    ACCOUNT_BLOCKED,

    /** The account exists but is inactive. */
    ACCOUNT_INACTIVE
}