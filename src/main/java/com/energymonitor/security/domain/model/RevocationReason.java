package com.energymonitor.security.domain.model;

/**
 * Why a session was revoked.
 *
 * <p>Revocation is a security statement, so the reason is part of the fact being recorded and
 * not decoration: an incident review distinguishes a logout from a session invalidated because
 * a refresh token was replayed, and from one invalidated because the password behind it was
 * changed. Free text would allow {@code "unknown"} or a typo, which is exactly the information
 * a reader needs.
 *
 * <p>The set is deliberately closed. Adding a reason means adding a value here, which is
 * cheap and forces the vocabulary to stay meaningful, rather than letting arbitrary strings
 * accumulate in the column.
 */
public enum RevocationReason {

    /**
     * A refresh token that had already been superseded was presented again. The family of that
     * token is treated as compromised, so this is the strongest of the three.
     */
    REFRESH_TOKEN_REUSE,

    /**
     * The password behind the session was changed or reset. Sessions that outlive the
     * credential that opened them should not stay usable.
     */
    PASSWORD_CHANGED,

    /**
     * Revoked by an operator, for instance after a reported compromise.
     */
    ADMINISTRATIVE
}
