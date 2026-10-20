package com.energymonitor.security.api;

import java.time.Instant;

/**
 * Published when a new account is created, by registration or by a first Google sign-in.
 *
 * @param userId     the new account
 * @param email      its address
 * @param occurredAt when it was created
 */
public record AccountRegistered(String userId, String email, Instant occurredAt) {
}
