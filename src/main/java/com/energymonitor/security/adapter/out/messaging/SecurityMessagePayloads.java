package com.energymonitor.security.adapter.out.messaging;

import java.time.Instant;

/**
 * The JSON bodies of the messages in {@link SecurityMessageTypes}, one record per type.
 *
 * <p>They are the wire contract, kept apart from the {@code api} records on purpose: a domain
 * event can gain a field without every consumer having to understand it, and a consumer never
 * needs a class of this service to read a message. Instants travel as ISO-8601 strings.
 */
public final class SecurityMessagePayloads {

    /** {@code account.registered} */
    public record AccountRegisteredPayload(String userId, String email, Instant occurredAt) {
    }

    /** {@code account.administered}; {@code action} is STATUS_CHANGED, ROLE_GRANTED or ROLE_REVOKED. */
    public record AccountAdministeredPayload(String actorId, String userId, String action,
                                             String detail, Instant occurredAt) {
    }

    /** {@code account.deleted} */
    public record AccountDeletedPayload(String userId, Instant deletedAt) {
    }

    /** {@code account.first-signed-in} */
    public record AccountFirstSignedInPayload(String userId, Instant occurredAt) {
    }

    /** {@code mail.email-verification} */
    public record EmailVerificationPayload(String userId, String recipient, String code,
                                           Instant validUntil) {
    }

    /** {@code mail.account-deletion}: the same shape as the verification mail. */
    public record AccountDeletionCodePayload(String userId, String recipient, String code,
                                             Instant validUntil) {
    }

    /** {@code mail.password-reset} */
    public record PasswordResetPayload(String userId, String recipient, String idResetToken,
                                       String code, Instant validUntil) {
    }

    private SecurityMessagePayloads() {
    }
}
