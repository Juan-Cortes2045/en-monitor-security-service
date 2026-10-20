package com.energymonitor.security.domain.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable record of a failed authentication attempt, for auditing and lockout analysis.
 *
 * <p>Once created it is never modified (INV-017), which is why every field is final.
 *
 * <p>The user identifier is optional because a failed attempt may target an account that does
 * not exist; in that case there is nothing to point at, and the persistence layer stores
 * {@code NULL} in {@code login_error_log.user_id}.
 *
 * <p>Maps to the {@code login_error_log} table. {@link #occurredAt()} maps to its
 * {@code created_at} column, which carries the event time.
 */
public final class LoginErrorLog {

    private static final int DESCRIPTION_MAX = 500;
    private static final int IP_ADDRESS_MAX = 45;
    private static final int IDENTIFIER_MAX = 10;

    private final String idLoginError;
    private final String idUser;
    private final LoginErrorType errorType;
    private final String description;
    private final String ipAddress;
    private final Instant occurredAt;

    /**
     * @param idLoginError identifier, {@code VARCHAR(10)}
     * @param idUser       affected user, {@code null} when the account is unknown
     * @param errorType    classification, required (INV-018)
     * @param description  optional detail
     * @param ipAddress    optional origin IP
     * @param occurredAt   when the attempt happened
     */
    public LoginErrorLog(String idLoginError, String idUser, LoginErrorType errorType,
                         String description, String ipAddress, Instant occurredAt) {
        this.idLoginError = Preconditions.text(idLoginError, "idLoginError");
        this.idUser = Preconditions.optionalText(idUser, IDENTIFIER_MAX, "idUser");
        this.errorType = Preconditions.notNull(errorType, "errorType");
        this.description = Preconditions.optionalText(description, DESCRIPTION_MAX, "description");
        this.ipAddress = Preconditions.optionalText(ipAddress, IP_ADDRESS_MAX, "ipAddress");
        this.occurredAt = Preconditions.notNull(occurredAt, "occurredAt");
        if (errorType.requiresKnownUser() && this.idUser == null) {
            throw new IllegalArgumentException(errorType + " requires an associated user");
        }
    }

    /**
     * Records an attempt that did not match any account.
     *
     * @param idLoginError identifier
     * @param ipAddress    optional origin IP
     * @param occurredAt   when the attempt happened
     * @return the log entry
     */
    public static LoginErrorLog userNotFound(String idLoginError, String ipAddress, Instant occurredAt) {
        return new LoginErrorLog(idLoginError, null, LoginErrorType.USER_NOT_FOUND, null, ipAddress, occurredAt);
    }

    /** @return the identifier */
    public String idLoginError() {
        return idLoginError;
    }

    /** @return the affected user identifier, empty when the account is unknown */
    public Optional<String> idUser() {
        return Optional.ofNullable(idUser);
    }

    /** @return the error classification */
    public LoginErrorType errorType() {
        return errorType;
    }

    /** @return description, empty when not recorded */
    public Optional<String> description() {
        return Optional.ofNullable(description);
    }

    /** @return origin IP, empty when not captured */
    public Optional<String> ipAddress() {
        return Optional.ofNullable(ipAddress);
    }

    /** @return the instant the attempt happened */
    public Instant occurredAt() {
        return occurredAt;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof LoginErrorLog that)) {
            return false;
        }
        return idLoginError.equals(that.idLoginError);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idLoginError);
    }

    @Override
    public String toString() {
        return "LoginErrorLog{idLoginError='" + idLoginError + "', errorType=" + errorType + "}";
    }
}
