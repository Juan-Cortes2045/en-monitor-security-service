package com.energymonitor.security.domain.model;

/**
 * Classification of a failed authentication attempt.
 *
 * <p>Mirrors the {@code ENUM} column {@code login_error_log.error_type}. Every value here
 * is a valid classification by construction (INV-018).
 */
public enum LoginErrorType {

    /** Credentials supplied did not match the stored hash. */
    INVALID_PASSWORD,

    /** No account exists for the supplied identifier. */
    USER_NOT_FOUND,

    /** The account exists but is blocked. */
    ACCOUNT_BLOCKED,

    /** The account exists but is inactive. */
    ACCOUNT_INACTIVE;

    /**
     * Whether this error can be attributed to a known account.
     *
     * <p>Only {@link #USER_NOT_FOUND} cannot: there is no {@code user} to point at, which
     * is why {@code login_error_log.user_id} is nullable.
     *
     * @return {@code true} when an associated user identifier is expected
     */
    public boolean requiresKnownUser() {
        return this != USER_NOT_FOUND;
    }
}
