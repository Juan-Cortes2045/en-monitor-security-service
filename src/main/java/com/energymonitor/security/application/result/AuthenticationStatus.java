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
    ACCOUNT_INACTIVE,

    /**
     * The password matched, but the account has not confirmed its address. Classified only after
     * the password check, so it tells nothing to whoever does not know the password.
     */
    EMAIL_NOT_VERIFIED,

    /**
     * The password matched and the address is verified, but the account never accepted the terms
     * and conditions, and the attempt did not accept them either. No session until it does.
     */
    TERMS_NOT_ACCEPTED
}