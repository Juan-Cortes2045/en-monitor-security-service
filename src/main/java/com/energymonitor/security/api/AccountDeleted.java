package com.energymonitor.security.api;

import java.time.Instant;

/**
 * Published when an account is deleted, inside the deleting transaction.
 *
 * <p>Other modules that keep data about the account by identifier react to it here instead of
 * being called by this module, which knows nothing about them. A listener that fails rolls the
 * deletion back with it.
 *
 * @param userId    the deleted account
 * @param deletedAt when it was deleted
 */
public record AccountDeleted(String userId, Instant deletedAt) {
}
