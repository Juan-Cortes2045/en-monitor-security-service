package com.energymonitor.security.domain.model;

/**
 * Account state of a {@link User}.
 *
 * <p>Mirrors the {@code ENUM('ACTIVE','INACTIVE','BLOCKED')} column of {@code user.status}.
 * Only {@link #ACTIVE} accounts are allowed to authenticate (INV-005).
 */
public enum UserStatus {

    /** Account enabled for authentication. */
    ACTIVE,

    /** Account temporarily unusable, e.g. pending email verification. */
    INACTIVE,

    /** Account blocked for security reasons. Cannot authenticate. */
    BLOCKED;

    /**
     * Whether an account in this state may authenticate.
     *
     * @return {@code true} only for {@link #ACTIVE}
     */
    public boolean allowsAuthentication() {
        return this == ACTIVE;
    }
}
