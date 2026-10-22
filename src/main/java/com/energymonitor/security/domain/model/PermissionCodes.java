package com.energymonitor.security.domain.model;

/**
 * The permission codes the platform enforces, seeded by {@code security-025-seed-admin-role}.
 *
 * <p>The code is the stable contract (INV-022): the filter chain enforces it and the web client
 * hard-codes it to decide what to render, so a value here must never change once released.
 *
 * <p>These are global permissions. They say nothing about any home: being an owner or a member
 * of a home is decided by the Home Management context, and none of these codes grants access to
 * a home's data.
 */
public final class PermissionCodes {

    /** Read the user directory and the role catalogue. */
    public static final String USER_READ = "USER.READ";

    /** Activate, deactivate or block an account. */
    public static final String USER_MANAGE = "USER.MANAGE";

    /** Grant or revoke global roles. */
    public static final String ROLE_MANAGE = "ROLE.MANAGE";

    /** Name of the seeded role that holds every permission above. */
    public static final String ADMIN_ROLE = "ADMIN";

    private PermissionCodes() {
    }
}
