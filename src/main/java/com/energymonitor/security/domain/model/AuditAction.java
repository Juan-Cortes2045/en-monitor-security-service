package com.energymonitor.security.domain.model;

/**
 * Security-relevant action recorded in an {@link AuditLog}.
 *
 * <p>Mirrors the {@code ENUM('CREATE','UPDATE','DELETE','LOGIN','LOGIN_FAILED','LOGOUT')}
 * column of {@code audit_log.action}.
 */
public enum AuditAction {

    /** A resource was created. */
    CREATE,

    /** A resource was modified. */
    UPDATE,

    /** A resource was deleted. */
    DELETE,

    /** A successful authentication occurred. */
    LOGIN,

    /** A failed authentication occurred. */
    LOGIN_FAILED,

    /** A session was closed. */
    LOGOUT;

    /**
     * Whether this action is part of the authentication trail.
     *
     * @return {@code true} for {@link #LOGIN}, {@link #LOGIN_FAILED} and {@link #LOGOUT}
     */
    public boolean isAuthenticationEvent() {
        return this == LOGIN || this == LOGIN_FAILED || this == LOGOUT;
    }
}
