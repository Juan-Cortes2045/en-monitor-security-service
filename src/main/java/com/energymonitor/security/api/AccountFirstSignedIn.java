package com.energymonitor.security.api;

import java.time.Instant;

/**
 * Published when an account signs in for the first time, its address already verified: by
 * password once the verification code was entered, or with Google. It is the moment to welcome
 * its owner.
 *
 * @param userId     the account
 * @param occurredAt when it signed in
 */
public record AccountFirstSignedIn(String userId, Instant occurredAt) {
}
