package com.energymonitor.security.domain.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable trail of a security-relevant {@link AuditAction}.
 *
 * <p>Every field is final on purpose: an audit record is never edited or deleted once written
 * (INV-023), so the class offers no mutators at all.
 *
 * <p>The user identifier is optional. The schema declares {@code audit_log.user_id} as
 * nullable, and a failed login against an unknown account has no user to point at.
 *
 * <p>Maps to the {@code audit_log} table. {@link #occurredAt()} maps to its {@code created_at}
 * column, which carries the event time. The technical {@code updated_at} and {@code deleted_at}
 * columns are not part of the domain.
 */
public final class AuditLog {

    private static final int DESCRIPTION_MAX = 255;
    private static final int APPLICATION_MAX = 255;
    private static final int IP_ADDRESS_MAX = 45;
    private static final int IDENTIFIER_MAX = 10;

    private final String idAuditLog;
    private final String idUser;
    private final AuditAction action;
    private final String description;
    private final String ipAddress;
    private final String application;
    private final Instant occurredAt;

    /**
     * @param idAuditLog identifier, {@code VARCHAR(10)}
     * @param idUser     responsible user, {@code null} when the actor is unknown
     * @param action     action performed, required
     * @param description optional detail
     * @param ipAddress  optional origin IP
     * @param application optional emitting application
     * @param occurredAt when the event happened
     */
    public AuditLog(String idAuditLog, String idUser, AuditAction action, String description,
                    String ipAddress, String application, Instant occurredAt) {
        this.idAuditLog = Preconditions.text(idAuditLog, "idAuditLog");
        this.idUser = Preconditions.optionalText(idUser, IDENTIFIER_MAX, "idUser");
        this.action = Preconditions.notNull(action, "action");
        this.description = Preconditions.optionalText(description, DESCRIPTION_MAX, "description");
        this.ipAddress = Preconditions.optionalText(ipAddress, IP_ADDRESS_MAX, "ipAddress");
        this.application = Preconditions.optionalText(application, APPLICATION_MAX, "application");
        this.occurredAt = Preconditions.notNull(occurredAt, "occurredAt");
    }

    /**
     * Records a successful login.
     *
     * @param idAuditLog identifier
     * @param user       the user who logged in
     * @param ipAddress  optional origin IP
     * @param occurredAt when it happened
     * @return the audit entry
     */
    public static AuditLog login(String idAuditLog, User user, String ipAddress, Instant occurredAt) {
        Preconditions.notNull(user, "user");
        return new AuditLog(idAuditLog, user.idUser(), AuditAction.LOGIN, null, ipAddress, null, occurredAt);
    }

    /**
     * Records a failed login. The user may be {@code null} when no account matched.
     *
     * @param idAuditLog identifier
     * @param user       the user, or {@code null} when the account is unknown
     * @param ipAddress  optional origin IP
     * @param occurredAt when it happened
     * @return the audit entry
     */
    public static AuditLog loginFailed(String idAuditLog, User user, String ipAddress, Instant occurredAt) {
        return new AuditLog(idAuditLog, user == null ? null : user.idUser(), AuditAction.LOGIN_FAILED,
                null, ipAddress, null, occurredAt);
    }

    /** @return the identifier */
    public String idAuditLog() {
        return idAuditLog;
    }

    /** @return the responsible user identifier, empty when the actor is unknown */
    public Optional<String> idUser() {
        return Optional.ofNullable(idUser);
    }

    /** @return the recorded action */
    public AuditAction action() {
        return action;
    }

    /** @return the description, empty when not recorded */
    public Optional<String> description() {
        return Optional.ofNullable(description);
    }

    /** @return the origin IP, empty when not captured */
    public Optional<String> ipAddress() {
        return Optional.ofNullable(ipAddress);
    }

    /** @return the emitting application, empty when not captured */
    public Optional<String> application() {
        return Optional.ofNullable(application);
    }

    /** @return when the event happened */
    public Instant occurredAt() {
        return occurredAt;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof AuditLog that)) {
            return false;
        }
        return idAuditLog.equals(that.idAuditLog);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idAuditLog);
    }

    @Override
    public String toString() {
        return "AuditLog{idAuditLog='" + idAuditLog + "', action=" + action + "}";
    }
}
