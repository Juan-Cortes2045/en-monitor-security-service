package com.energymonitor.security.domain.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Persisted authenticated session of a {@link User}.
 *
 * <p>A session is valid only while it has not been revoked, not been closed and not expired
 * (INV-011). The refresh token value is stored opaquely: nothing about signing it belongs to
 * the domain.
 *
 * <h2>Revocation and closure are different events</h2>
 *
 * <p>Both end the session, and the difference is why, which decides what a later operator can
 * conclude from the row:
 *
 * <ul>
 *   <li>{@link #revoke()} records a <em>security invalidation</em>: the credential is or may be
 *       in someone else's hands. Reuse of a superseded refresh token, a password reset, an
 *       administrative decision or a suspected theft all belong here.</li>
 *   <li>{@link #close(Instant)} records <em>ordinary termination</em>: the holder walked away.
 *       Logout is the ordinary case.</li>
 * </ul>
 *
 * <p>They are kept distinct because collapsing them loses the ability to tell, months later,
 * whether an account was attacked or merely used. A revoked session is terminal and is never
 * expected to come back; a closed one has simply ended. Neither operation converts into the
 * other: closing never marks a session as compromised, and revoking never stamps a departure
 * time.
 *
 * <p>Both record the first event and ignore later ones, so the instant recorded is the instant
 * the fact became true.
 *
 * <p><strong>Known limitation, carried into the next step:</strong> {@code revokedAt} and
 * {@code revokedReason} exist in the domain but have no column to live in, because adding one
 * requires a Liquibase change that belongs with the refresh-token migration. A session rehydrated
 * from the database therefore always comes back with an empty revocation instant and reason,
 * even when the {@code revoked} flag is set. Nothing exercises that gap today, because the only
 * production caller of revocation is being switched to {@code close()} by the session capability
 * work, and the flows that revoke (password change, token reuse) arrive later. The columns must
 * land before any of those flows reaches the database.
 *
 * <p>Maps to the {@code user_session} table.
 *
 * <h2>Why refresh tokens will move to their own table</h2>
 *
 * <p>{@code refreshToken} is a field of this aggregate today, and that is the design decision
 * this class records for the next step. At present one row is <em>both</em> the session and
 * the refresh token, which is why rotation cannot be modelled: there is no way to replace the
 * token while keeping the session, because the session <em>is</em> the token, and a rotated
 * token would have to become a second session for the same login.
 *
 * <p>Rotation also needs to answer a question this structure cannot answer. Given a lineage
 *
 * <pre>
 *   R1 -&gt; R2 -&gt; R3      (one family)
 * </pre>
 *
 * a presentation of {@code R1} after {@code R3} is a theft signal, and answering it requires
 * knowing that {@code R1} belongs to the same family as the current token. A single row can
 * only remember its immediate predecessor, so after two rotations the oldest token is
 * indistinguishable from an expired or a forged one.
 *
 * <p>The decision is therefore to keep the session here and move the token lineage into a
 * separate {@code refresh_token} table that references this one. Each row there carries the
 * session it belongs to, the family it descends from, and the token that replaced it, which
 * makes both the current and the superseded token addressable, lets a replay of any ancestor
 * be recognised, and lets the whole family be revoked in one operation.
 *
 * <p>Separating them also keeps the extractability this modular monolith is being shaped for:
 * session lifetime and token rotation are different concerns with different rates of change,
 * and a table that owns only the token lineage can move to an authentication service without
 * dragging session metadata along.
 *
 * <p>Nothing of that exists yet. This class still holds a single {@code refreshToken} and the
 * schema still has one row per session, because the field and the column have to be replaced
 * together and that replacement belongs with the refresh flow rather than ahead of it.
 */
public class UserSession {

    private static final int IP_ADDRESS_MAX = 45;
    private static final int USER_AGENT_MAX = 150;

    private final String idUserSession;
    private final String idUser;
    private final Instant createdAt;
    private Instant expirationAt;
    private final String ipAddress;
    private final String userAgent;
    private boolean revoked;
    private Instant revokedAt;
    private RevocationReason revokedReason;
    private Instant closedAt;

    /**
     * Rehydrates a stored session.
     *
     * <p>Revocation and closure are restored independently, so a session that was both revoked
     * and closed keeps both facts. A row that claims to be revoked without an instant is
     * accepted: the column pair does not exist yet in the schema, so older rows and rows
     * written before revocation was timestamped legitimately carry the flag alone.
     *
     * @param idUserSession identifier, {@code VARCHAR(10)}
     * @param idUser        owning user
     * @param createdAt     session start
     * @param expirationAt  session expiry
     * @param ipAddress     optional client IP
     * @param userAgent     optional client agent
     * @param revoked       whether it was already revoked
     * @param revokedAt     when it was revoked, {@code null} when not revoked or not yet recorded
     * @param revokedReason why it was revoked, {@code null} when not revoked or not yet recorded
     * @param closedAt      closure instant, {@code null} while open
     * @throws IllegalStateException if the expiration is not after the creation
     */
    public UserSession(String idUserSession, String idUser,
                       Instant createdAt, Instant expirationAt, String ipAddress,
                       String userAgent, boolean revoked, Instant revokedAt,
                       RevocationReason revokedReason, Instant closedAt) {
        this.idUserSession = Preconditions.text(idUserSession, "idUserSession");
        this.idUser = Preconditions.text(idUser, "idUser");
        this.createdAt = Preconditions.notNull(createdAt, "createdAt");
        this.expirationAt = Preconditions.notNull(expirationAt, "expirationAt");
        Preconditions.expirationAfter(createdAt, expirationAt);
        this.ipAddress = Preconditions.optionalText(ipAddress, IP_ADDRESS_MAX, "ipAddress");
        this.userAgent = Preconditions.optionalText(userAgent, USER_AGENT_MAX, "userAgent");
        this.revoked = revoked;
        this.revokedAt = revokedAt;
        this.revokedReason = revokedReason;
        this.closedAt = closedAt;
    }

    /**
     * Opens a new session.
     *
     * @param idUserSession identifier
     * @param idUser        owning user
     * @param createdAt     session start
     * @param expirationAt  session expiry
     * @param ipAddress     optional client IP
     * @param userAgent     optional client agent
     * @return a fresh, open session
     * @throws IllegalStateException if the expiration is not after the creation
     */
    public static UserSession open(String idUserSession, String idUser,
                                   Instant createdAt, Instant expirationAt, String ipAddress,
                                   String userAgent) {
        return new UserSession(idUserSession, idUser, createdAt, expirationAt,
                ipAddress, userAgent, false, null, null, null);
    }

    /** @return the identifier */
    public String idUserSession() {
        return idUserSession;
    }

    /** @return owning user identifier */
    public String idUser() {
        return idUser;
    }

    /** @return session start instant */
    public Instant createdAt() {
        return createdAt;
    }

    /** @return session expiry instant */
    public Instant expirationAt() {
        return expirationAt;
    }

    /** @return client IP, empty when not captured */
    public Optional<String> ipAddress() {
        return Optional.ofNullable(ipAddress);
    }

    /** @return client user agent, empty when not captured */
    public Optional<String> userAgent() {
        return Optional.ofNullable(userAgent);
    }

    /** @return whether the session was revoked */
    public boolean isRevoked() {
        return revoked;
    }

    /** @return when it was revoked, empty when not revoked or not yet recorded */
    public Optional<Instant> revokedAt() {
        return Optional.ofNullable(revokedAt);
    }

    /** @return why it was revoked, empty when not revoked or not yet recorded */
    public Optional<RevocationReason> revokedReason() {
        return Optional.ofNullable(revokedReason);
    }

    /** @return closure instant, empty while the session is open */
    public Optional<Instant> closedAt() {
        return Optional.ofNullable(closedAt);
    }

    /**
     * Whether the session has reached its expiry.
     *
     * @param now reference instant
     * @return {@code true} when expired
     */
    public boolean isExpired(Instant now) {
        Preconditions.notNull(now, "now");
        return !now.isBefore(expirationAt);
    }

    /**
     * Whether the session may still be used: not revoked, not closed, not expired (INV-011).
     *
     * @param now reference instant
     * @return {@code true} when the session is active
     */
    public boolean isActive(Instant now) {
        Preconditions.notNull(now, "now");
        return !revoked && closedAt == null && !isExpired(now);
    }

    /**
     * Slides the session window forward because its credential was rotated.
     *
     * <p>The session no longer stores a secret, so there is nothing here to replace: rotating a
     * refresh token is recorded on {@link RefreshToken}, and what the session does is move its
     * own expiry so the login stays alive alongside the new generation. Identity, owner,
     * creation instant and client data are all untouched, which is the separation the
     * {@code RefreshToken} aggregate exists to express: the secret changes, the login does not.
     *
     * <p>The original {@code createdAt} is deliberately left alone rather than moved forward.
     * A session that has been rotating for three weeks did not start three weeks ago, and
     * overwriting the creation instant would make the session's own age unrecoverable and would
     * let a client extend the window indefinitely without it being visible anywhere.
     *
     * <p>Only a live session may be extended. A revoked, closed or expired one is refused
     * rather than resurrected: this is how an active login stays active, and allowing it on a
     * dead session would hand out a fresh window for a login that should be over.
     *
     * <p>Arguments are validated before state, matching the rest of the domain: a null or
     * impossible instant is a caller mistake, and reporting it is more useful than reporting
     * the state.
     *
     * <p>The reference instant is a parameter rather than a clock call because the domain holds
     * no clock, and because the caller has to state when the rotation happens anyway. It is
     * used to decide whether the session is still alive and to check that the new window lies
     * in the future; it is not stored, because the instant of the rotation belongs to
     * {@link RefreshToken}, which is where the new generation is recorded.
     *
     * @param newExpiration when the session now stops being valid, strictly after the rotation
     * @param rotatedAt     the reference instant of the rotation
     * @throws IllegalArgumentException if either instant is null
     * @throws IllegalStateException    if the new window is not strictly forward, or if the
     *                                  session is revoked, closed or already expired
     */
    public void rotate(Instant newExpiration, Instant rotatedAt) {
        Preconditions.notNull(newExpiration, "newExpiration");
        Preconditions.notNull(rotatedAt, "rotatedAt");
        Preconditions.expirationAfter(rotatedAt, newExpiration);
        if (revoked) {
            throw new IllegalStateException("a revoked session cannot be rotated");
        }
        if (closedAt != null) {
            throw new IllegalStateException("a closed session cannot be rotated");
        }
        if (isExpired(rotatedAt)) {
            throw new IllegalStateException("an expired session cannot be rotated");
        }
        this.expirationAt = newExpiration;
    }

    /**
     * Revokes the session as a security measure, recording when and why.
     *
     * <p>Use this when the credential is or may be compromised: reuse of a superseded refresh
     * token, a password change or reset, an operator decision. It is deliberately not the
     * operation for an ordinary logout, which is {@link #close(Instant)} instead.
     *
     * <p>Revocation is terminal and idempotent, and the first revocation is the one that
     * stands. A later call is ignored rather than overwriting, so a second revocation carrying
     * a later instant or a different reason cannot rewrite the moment the problem was first
     * detected, which is the fact worth preserving.
     *
     * <p>This method refuses nothing about the current state. A session that was already closed
     * can still be revoked, because revocation is a statement about the credential and remains
     * true regardless of how the session ended. That matters when a password change revokes
     * every session a user holds, some of which are already closed.
     *
     * <p>It does not close the session either: {@code closedAt} is left untouched, so a revoked
     * session remains distinguishable from a closed one when the row is read later.
     *
     * @param revokedAt when the revocation happened
     * @param reason    why the session was revoked
     * @throws IllegalArgumentException if the instant or the reason is null
     */
    public void revoke(Instant revokedAt, RevocationReason reason) {
        Preconditions.notNull(revokedAt, "revokedAt");
        Preconditions.notNull(reason, "revokedReason");
        if (revoked) {
            return;
        }
        this.revoked = true;
        this.revokedAt = revokedAt;
        this.revokedReason = reason;
    }

    /**
     * Closes the session at the given instant, ending it normally.
     *
     * <p>Use this for logout and any other voluntary end of use. Closing is not a security
     * judgement about the credential, which is what separates it from {@link #revoke(Instant,
     * RevocationReason)}: closing leaves {@code revoked} untouched, and a closed session is
     * never marked as compromised.
     *
     * <p>Like revocation, closing is idempotent and the first closure is the one that stands,
     * so a repeated logout cannot move the recorded departure time. Closing an already revoked
     * session is allowed and changes nothing about the revocation.
     *
     * @param instant closure time
     * @throws IllegalArgumentException if the instant is null
     */
    public void close(Instant instant) {
        Preconditions.notNull(instant, "instant");
        if (closedAt != null) {
            return;
        }
        this.closedAt = instant;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof UserSession that)) {
            return false;
        }
        return idUserSession.equals(that.idUserSession);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idUserSession);
    }

    @Override
    public String toString() {
        return "UserSession{idUserSession='" + idUserSession + "', idUser='" + idUser
                + "', revoked=" + revoked + "}";
    }
}
