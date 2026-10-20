package com.energymonitor.security.domain.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * One generation of a refresh token, belonging to a session and to a family of generations.
 *
 * <p>The split from {@link UserSession} is the reason this type exists. A session is a login:
 * who connected, from where, since when. A refresh token is a renewable secret hanging off that
 * login. Rotating the secret must not mint a second login, so the two are separate objects and
 * the session keeps its identity while generations accumulate against it.
 *
 * <h2>Lineage</h2>
 *
 * <p>Every generation records two things about its ancestry. {@code familyId} names the root of
 * the chain and is copied unchanged by every descendant, so all generations of one login share
 * it. {@code parentId} names the generation this one replaced and is empty on the root. Together
 * they make any token resolvable to the login it belongs to, and make a retired token
 * recognisable as retired rather than unknown.
 *
 * <pre>
 *   R1 (family F, parent empty, ACTIVE)
 *    └─ R2 (family F, parent R1, ACTIVE)
 *        └─ R3 (family F, parent R2, ACTIVE)
 * </pre>
 *
 * <p>When R2 is retired it becomes {@code ROTATED}, not deleted. A later presentation of R2 is
 * therefore distinguishable from a forged token, which is what turns replay into a security
 * event instead of a generic rejection.
 *
 * <h2>Only the hash is held</h2>
 *
 * <p>This aggregate never sees the secret. It stores {@code tokenHash}, produced by a hashing
 * port, and has no field, accessor or constructor parameter that could carry the raw value. The
 * secret is generated, hashed and handed to the client within the login or refresh that mints
 * it, and does not survive that call.
 *
 * <p>Maps to the {@code refresh_token} table.
 */
public class RefreshToken {

    /** Matches {@code refresh_token.id_refresh_token} and the {@code VARCHAR(10)} id columns. */
    private static final int ID_MAX = 10;

    /** Lowercase hex SHA-256 renders 32 bytes as 64 characters. */
    private static final int TOKEN_HASH_MAX = 64;

    private final String idRefreshToken;
    private final String idUserSession;
    private final String familyId;
    private final String parentId;
    private final String tokenHash;
    private final Instant createdAt;
    private final Instant expiresAt;
    private RefreshTokenStatus status;
    private Instant rotatedAt;
    private Instant revokedAt;
    private RevocationReason revokedReason;

    /**
     * Rehydrates a stored generation.
     *
     * <p>Lifecycle stamps are taken from the row as they are. A row that claims a status
     * without the matching stamp is accepted rather than rejected: the columns arrived in
     * different migrations, and a domain that refused to represent a readable row would push
     * the problem into the persistence layer.
     *
     * @param idRefreshToken identifier, {@code VARCHAR(10)}
     * @param idUserSession  session this generation belongs to
     * @param familyId       root of the chain, shared by every descendant
     * @param parentId       generation this one replaced, {@code null} on the root
     * @param tokenHash      hash of the secret, never the secret
     * @param status         lifecycle status
     * @param createdAt      issue instant
     * @param expiresAt      expiry instant, strictly after {@code createdAt}
     * @param rotatedAt      when it was rotated, {@code null} unless {@link RefreshTokenStatus#ROTATED}
     * @param revokedAt      when it was revoked, {@code null} unless {@link RefreshTokenStatus#REVOKED}
     * @param revokedReason  why it was revoked, {@code null} unless {@link RefreshTokenStatus#REVOKED}
     * @throws IllegalStateException if the expiry is not strictly after the issue instant
     */
    public RefreshToken(String idRefreshToken, String idUserSession, String familyId,
                        String parentId, String tokenHash, RefreshTokenStatus status,
                        Instant createdAt, Instant expiresAt, Instant rotatedAt,
                        Instant revokedAt, RevocationReason revokedReason) {
        this.idRefreshToken = Preconditions.text(idRefreshToken, ID_MAX, "idRefreshToken");
        this.idUserSession = Preconditions.text(idUserSession, ID_MAX, "idUserSession");
        this.familyId = Preconditions.text(familyId, ID_MAX, "familyId");
        this.parentId = Preconditions.optionalText(parentId, ID_MAX, "parentId");
        this.tokenHash = Preconditions.text(tokenHash, TOKEN_HASH_MAX, "tokenHash");
        this.status = Preconditions.notNull(status, "status");
        this.createdAt = Preconditions.notNull(createdAt, "createdAt");
        this.expiresAt = Preconditions.notNull(expiresAt, "expiresAt");
        Preconditions.expirationAfter(createdAt, expiresAt);
        this.rotatedAt = rotatedAt;
        this.revokedAt = revokedAt;
        this.revokedReason = revokedReason;
    }

    /**
     * Issues the root generation of a new family, which is the generation that starts a login.
     *
     * <p>The root is its own family: {@code familyId} is the identifier of the generation
     * itself, and {@code parentId} is empty because nothing preceded it. Every later generation
     * inherits that {@code familyId}.
     *
     * @param idRefreshToken identifier for this generation
     * @param idUserSession  session the login owns
     * @param tokenHash      hash of the freshly generated secret
     * @param createdAt      issue instant
     * @param expiresAt      expiry instant, strictly after {@code createdAt}
     * @return an active root generation
     * @throws IllegalStateException if the expiry is not strictly after the issue instant
     */
    public static RefreshToken root(String idRefreshToken, String idUserSession, String tokenHash,
                                    Instant createdAt, Instant expiresAt) {
        return new RefreshToken(idRefreshToken, idUserSession, idRefreshToken, null, tokenHash,
                RefreshTokenStatus.ACTIVE, createdAt, expiresAt, null, null, null);
    }

    /**
     * Issues a replacement generation, the child of a token that is being rotated.
     *
     * <p>The child inherits the family of its parent and points at it, which is the whole of
     * the lineage: same family, one step further from the root, same session. The parent is
     * not touched here; the caller retires it separately so the two writes belong to one
     * transaction.
     *
     * @param idRefreshToken identifier for the new generation
     * @param parent         the generation being replaced, which supplies family and session
     * @param tokenHash      hash of the freshly generated secret
     * @param createdAt      issue instant
     * @param expiresAt      expiry instant, strictly after {@code createdAt}
     * @return an active child generation
     * @throws IllegalStateException if the expiry is not strictly after the issue instant
     */
    public static RefreshToken childOf(RefreshToken parent, String idRefreshToken,
                                       String tokenHash, Instant createdAt, Instant expiresAt) {
        Preconditions.notNull(parent, "parent");
        return new RefreshToken(idRefreshToken, parent.idUserSession, parent.familyId,
                parent.idRefreshToken, tokenHash, RefreshTokenStatus.ACTIVE, createdAt, expiresAt,
                null, null, null);
    }

    /** @return the identifier */
    public String idRefreshToken() {
        return idRefreshToken;
    }

    /** @return the session this generation belongs to */
    public String idUserSession() {
        return idUserSession;
    }

    /** @return the root of the chain, shared by every descendant */
    public String familyId() {
        return familyId;
    }

    /** @return the generation this one replaced, empty on the root */
    public Optional<String> parentId() {
        return Optional.ofNullable(parentId);
    }

    /** @return whether this generation is the root of its family */
    public boolean isRoot() {
        return parentId == null;
    }

    /** @return the stored hash, never the secret */
    public String tokenHash() {
        return tokenHash;
    }

    /** @return the stored lifecycle status */
    public RefreshTokenStatus status() {
        return status;
    }

    /** @return issue instant */
    public Instant createdAt() {
        return createdAt;
    }

    /** @return expiry instant */
    public Instant expiresAt() {
        return expiresAt;
    }

    /** @return when it was rotated, empty unless rotated */
    public Optional<Instant> rotatedAt() {
        return Optional.ofNullable(rotatedAt);
    }

    /** @return when it was revoked, empty unless revoked */
    public Optional<Instant> revokedAt() {
        return Optional.ofNullable(revokedAt);
    }

    /** @return why it was revoked, empty unless revoked */
    public Optional<RevocationReason> revokedReason() {
        return Optional.ofNullable(revokedReason);
    }

    /**
     * Whether the generation has outlived its expiry.
     *
     * @param now reference instant
     * @return {@code true} when the expiry has been reached
     */
    public boolean isExpired(Instant now) {
        Preconditions.notNull(now, "now");
        return !now.isBefore(expiresAt);
    }

    /**
     * Whether presenting this token authorises a rotation right now.
     *
     * <p>Only an active generation that has not aged out qualifies. This is the single place
     * that decides it, so the reuse flow and the legitimate flow cannot disagree about what a
     * usable token looks like.
     *
     * @param now reference instant
     * @return {@code true} when the token may be exchanged
     */
    public boolean isUsable(Instant now) {
        return status == RefreshTokenStatus.ACTIVE && !isExpired(now);
    }

    /**
     * Whether presenting this token again is a replay rather than a mistake.
     *
     * <p>True only for a {@link RefreshTokenStatus#ROTATED} generation. A revoked or expired
     * one is simply not usable, which is a different situation and must not be escalated: a
     * replay means a secret that was already spent is still in circulation, whereas an expired
     * token means the client was slow.
     *
     * @return {@code true} when this generation was already spent
     */
    public boolean isReplayed() {
        return status == RefreshTokenStatus.ROTATED;
    }

    /**
     * Retires this generation because its secret has been replaced.
     *
     * <p>The row is kept rather than deleted. That is the point: a deleted predecessor would
     * make a replay of it look like an unknown token, and the theft would go unnoticed. Keeping
     * it as {@code ROTATED} is what lets the next presentation be recognised as a replay.
     *
     * <p>Only an active generation can be rotated, and only once. Revoked, expired and
     * already-rotated generations are refused, so no terminal state can be walked backwards.
     *
     * @param rotatedAt when the replacement was issued
     * @throws IllegalArgumentException if the instant is null
     * @throws IllegalStateException    if the generation is not active, which includes one
     *                                  that has already been rotated
     */
    public void rotate(Instant rotatedAt) {
        Preconditions.notNull(rotatedAt, "rotatedAt");
        if (status != RefreshTokenStatus.ACTIVE) {
            throw new IllegalStateException(
                    "a " + status + " token cannot be rotated");
        }
        this.status = RefreshTokenStatus.ROTATED;
        this.rotatedAt = rotatedAt;
    }

    /**
     * Invalidates this generation for a security reason.
     *
     * <p>Idempotent, and the first revocation is the one that stands: a later call carrying a
     * different instant or reason cannot rewrite when the problem was first detected. Rotating
     * a token that was already revoked is refused outright, because a secret that was
     * invalidated and then replaced would re-open a window that was deliberately closed.
     *
     * <p>Revoking does not touch {@code rotatedAt}, so a generation that was both spent and
     * then revoked keeps both facts and remains recognisable as a replay.
     *
     * @param revokedAt when the invalidation happened
     * @param reason    why
     * @throws IllegalArgumentException if the instant or the reason is null
     * @throws IllegalStateException    if the generation was already rotated
     */
    public void revoke(Instant revokedAt, RevocationReason reason) {
        Preconditions.notNull(revokedAt, "revokedAt");
        Preconditions.notNull(reason, "revokedReason");
        if (status == RefreshTokenStatus.ROTATED) {
            throw new IllegalStateException("a rotated token cannot be revoked; it is already spent");
        }
        if (status == RefreshTokenStatus.REVOKED) {
            return;
        }
        this.status = RefreshTokenStatus.REVOKED;
        this.revokedAt = revokedAt;
        this.revokedReason = reason;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof RefreshToken that)) {
            return false;
        }
        return idRefreshToken.equals(that.idRefreshToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idRefreshToken);
    }

    @Override
    public String toString() {
        return "RefreshToken{idRefreshToken='" + idRefreshToken + "', idUserSession='"
                + idUserSession + "', familyId='" + familyId + "', status=" + status + "}";
    }
}
