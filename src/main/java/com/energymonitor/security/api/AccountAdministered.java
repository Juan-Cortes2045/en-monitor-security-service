package com.energymonitor.security.api;

import java.time.Instant;

/**
 * Published when an administrator changes another account: its status or its global roles.
 * Only real changes are published; repeating a grant or revoking a role not held is not.
 *
 * @param actorId    the administrator who made the change
 * @param userId     the account that was changed
 * @param action     what was changed
 * @param detail     the new status ({@code BLOCKED}) or the role name ({@code ADMIN})
 * @param occurredAt when it happened
 */
public record AccountAdministered(String actorId, String userId, Action action, String detail,
                                  Instant occurredAt) {

    /** The kind of change. */
    public enum Action {
        STATUS_CHANGED,
        ROLE_GRANTED,
        ROLE_REVOKED
    }
}
