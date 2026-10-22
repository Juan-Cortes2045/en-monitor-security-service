package com.energymonitor.security.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Single-use token allowing a {@link User} to recover their password.
 *
 * <p>The domain tracks validity only. Generating the random token, hashing it and handing it to
 * a delivery channel belong to the application and its adapters, which arrive here with a token
 * already populated.
 *
 * <h2>Only the hash is stored</h2>
 *
 * <p>What reaches the database is {@link #resetTokenHash()}, the digest of the secret, and
 * nothing else. A disclosure of {@code password_reset_token} therefore hands over no credential
 * that could be redeemed, which is the whole reason for the column being named
 * {@code reset_token_hash}.
 *
 * <p>The clear secret is nevertheless present on a freshly issued token, as
 * {@link #clearToken()}, because someone has to deliver it to the account owner and this is the
 * last place it exists outside the request that generated it. It is transient by construction:
 * the persistence mapping has no field for it, so it cannot be written to a column even by
 * mistake, and a token read back from the database carries none. That is the difference from
 * {@link RefreshToken}, which never sees its secret at all - a refresh token is handed straight
 * back to the client that asked, while a reset token has to be pushed somewhere the client is
 * not holding.
 *
 * <p>Maps to the {@code password_reset_token} table.
 */
public class PasswordResetToken {

    /** Matches {@code password_reset_token.id_reset_token VARCHAR(10)}. */
    private static final int ID_MAX = 10;

    /** Lowercase hex HMAC-SHA256 renders 32 bytes as 64 characters. */
    private static final int TOKEN_HASH_MAX = 64;

    /**
     * How many times a code may be presented before it stops being redeemable (INV-011).
     *
     * <p>This is what makes a six-digit code defensible. The space is small enough to exhaust by
     * brute force over the network, so the bound has to exist somewhere; per code it is narrow
     * enough that a caller who mistypes twice still has room, and wide enough that guessing five
     * numbers is not a strategy.
     */
    private static final int MAX_ATTEMPTS = 5;

    private final String idResetToken;
    private final String idUser;
    private final String resetTokenHash;
    private final Instant createdAt;
    private final Instant expirationAt;

    /**
     * The secret in clear text, in memory only. {@code null} on a rehydrated token, which is
     * why it is exposed as an {@link Optional}: a caller that needs it has to ask, and the
     * empty case is a fact about the token rather than an accident.
     */
    private final String clearToken;

    private boolean used;

    /**
     * Redemption attempts already reserved for this code.
     *
     * <p>Written by a conditional update rather than by reading and writing this field, so the
     * count cannot be lost to two requests arriving together. See the persistence adapter.
     */
    private int attempts;

    /**
     * Issues a token. It starts unused and, provided the expiration is in the future, valid.
     *
     * @param idResetToken   identifier, {@code VARCHAR(10)}
     * @param idUser         user the token was issued to
     * @param clearToken     the random secret, held in memory for delivery and never stored
     * @param resetTokenHash hash of {@code clearToken}, the only part that is persisted
     * @param createdAt      issue instant
     * @param expirationAt   expiry instant, must be after {@code createdAt}
     * @return the issued token
     * @throws IllegalArgumentException if the identifier, the secret or the hash is missing
     * @throws IllegalStateException    if the expiration is not after the creation
     */
    public static PasswordResetToken issue(String idResetToken, String idUser, String clearToken,
                                          String resetTokenHash, Instant createdAt,
                                          Instant expirationAt) {
        return new PasswordResetToken(idResetToken, idUser, resetTokenHash, createdAt,
                expirationAt, clearToken, false, 0);
    }

    /**
     * Rehydrates a stored token, used state included.
     *
     * <p>Enforces the same validity window as {@link #issue(String, String, String, String,
     * Instant, Instant)}. Coming from the database does not excuse an impossible state: a row
     * whose expiry precedes its creation is corrupt, and the domain refuses to represent it
     * rather than letting it travel through the application.
     *
     * <p>There is no clear secret to restore, because none was ever stored.
     *
     * @param idResetToken   identifier
     * @param idUser         user the token belongs to
     * @param resetTokenHash the stored hash
     * @param createdAt      issue instant
     * @param expirationAt   expiry instant
     * @param used           whether it has already been used
     * @return the rehydrated token
     * @throws IllegalArgumentException if the identifier or the hash is missing
     * @throws IllegalStateException    if the expiration is not after the creation
     */
    public static PasswordResetToken rehydrate(String idResetToken, String idUser,
                                               String resetTokenHash, Instant createdAt,
                                               Instant expirationAt, boolean used, int attempts) {
        return new PasswordResetToken(idResetToken, idUser, resetTokenHash, createdAt,
                expirationAt, null, used, attempts);
    }

    /**
     * @param clearToken the secret to keep for delivery, or {@code null} when there is none,
     *                   which is the case for every token that came from the database
     */
    private PasswordResetToken(String idResetToken, String idUser, String resetTokenHash,
                               Instant createdAt, Instant expirationAt, String clearToken,
                               boolean used, int attempts) {
        this.idResetToken = Preconditions.text(idResetToken, ID_MAX, "idResetToken");
        this.idUser = Preconditions.text(idUser, ID_MAX, "idUser");
        this.resetTokenHash = Preconditions.text(resetTokenHash, TOKEN_HASH_MAX, "resetTokenHash");
        this.createdAt = Preconditions.notNull(createdAt, "createdAt");
        this.expirationAt = Preconditions.notNull(expirationAt, "expirationAt");
        Preconditions.expirationAfter(createdAt, expirationAt);
        this.clearToken = clearToken == null
                ? null
                : Preconditions.text(clearToken, "clearToken");
        this.used = used;
        if (attempts < 0) {
            throw new IllegalArgumentException("attempts must not be negative, got " + attempts);
        }
        this.attempts = attempts;
    }

    /** @return the identifier */
    public String idResetToken() {
        return idResetToken;
    }

    /** @return the user the token was issued to */
    public String idUser() {
        return idUser;
    }

    /** @return the stored hash, never the secret */
    public String resetTokenHash() {
        return resetTokenHash;
    }

    /**
     * The clear secret, for the delivery channel that has to hand it to the account owner.
     *
     * @return the secret while the issuing request is still in flight, empty on a token that
     *         came from the database
     */
    public Optional<String> clearToken() {
        return Optional.ofNullable(clearToken);
    }

    /** @return issue instant */
    public Instant createdAt() {
        return createdAt;
    }

    /** @return expiry instant */
    public Instant expirationAt() {
        return expirationAt;
    }

    /** @return whether the token has already been consumed */
    public boolean isUsed() {
        return used;
    }

    /**
     * Time remaining before expiry.
     *
     * @param now reference instant
     * @return the remaining duration, zero when already expired
     */
    public Duration remainingValidity(Instant now) {
        Preconditions.notNull(now, "now");
        Duration remaining = Duration.between(now, expirationAt);
        return remaining.isNegative() ? Duration.ZERO : remaining;
    }

    /**
     * Whether the token is past its expiry at the given instant (INV-009).
     *
     * @param now reference instant
     * @return {@code true} when expired
     */
    public boolean isExpired(Instant now) {
        Preconditions.notNull(now, "now");
        return !now.isBefore(expirationAt);
    }

    /**
     * Whether the token may still be redeemed: neither used nor expired, and with attempts left.
     *
     * <p>A code that has exhausted its attempts is as unusable as a consumed one, and reports
     * itself the same way, so that presenting it cannot be told apart from presenting it twice.
     *
     * @param now reference instant
     * @return {@code true} when the token is usable
     */
    public boolean isValid(Instant now) {
        return !used && !isExpired(now) && hasAttemptsLeft();
    }

    /**
     * Attempts already reserved against this code.
     *
     * @return how many of {@value #MAX_ATTEMPTS} have been used
     */
    public int attempts() {
        return attempts;
    }

    /**
     * Whether the code still has an attempt to spend.
     *
     * @return {@code true} when fewer than {@value #MAX_ATTEMPTS} attempts are recorded
     */
    public boolean hasAttemptsLeft() {
        return attempts < MAX_ATTEMPTS;
    }

    /**
     * Consumes the token. A used token can never be reused (INV-010).
     *
     * @throws IllegalStateException if the token was already used
     */
    public void markUsed() {
        if (used) {
            throw new IllegalStateException("password reset token has already been used");
        }
        this.used = true;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof PasswordResetToken that)) {
            return false;
        }
        return idResetToken.equals(that.idResetToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idResetToken);
    }

    @Override
    public String toString() {
        return "PasswordResetToken{idResetToken='" + idResetToken + "', idUser='" + idUser
                + "', used=" + used + "}";
    }
}
