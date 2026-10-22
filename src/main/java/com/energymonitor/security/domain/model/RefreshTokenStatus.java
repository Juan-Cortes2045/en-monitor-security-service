package com.energymonitor.security.domain.model;

/**
 * Where a refresh token generation stands in its lifecycle.
 *
 * <p>A generation is created {@link #ACTIVE} and never returns to it. Every other value is
 * terminal, and the distinction between them is what turns a replay into a detectable event
 * rather than a failed lookup.
 *
 * <h2>Only three of these are persisted</h2>
 *
 * <p>{@link #ACTIVE}, {@link #ROTATED} and {@link #REVOKED} are written to the column, because
 * each records a decision somebody took and each must survive a restart: the first authorises,
 * the second makes a replay recognisable, the third records an invalidation.
 *
 * <p>{@link #EXPIRED} is <strong>derived, never stored</strong>. A token ageing out is not a
 * decision, it is arithmetic: {@code expiresAt} has been passed. Writing it would mean a
 * background job mutating rows purely to restate what the clock already says, and it would
 * introduce a second thing that has to be kept in step with time. The value exists in the enum
 * and in the column's allowed literals so a future lifecycle job can use it, but nothing writes
 * it and no behaviour depends on it.
 *
 * <p>The consequence is the state machine the application actually applies, all of it decided
 * by {@code isUsable}, {@code isReplayed} and {@code isExpired} rather than by reading the
 * column:
 *
 * <table>
 *   <caption>How each stored state behaves</caption>
 *   <tr><th>Stored state</th><th>{@code expiresAt}</th><th>Outcome</th></tr>
 *   <tr><td>{@code ACTIVE}</td><td>in the future</td><td>rotates; the token is retired and a
 *       successor is issued</td></tr>
 *   <tr><td>{@code ACTIVE}</td><td>in the past</td><td>rejected as expired; nothing is written
 *       and nothing is escalated</td></tr>
 *   <tr><td>{@code ROTATED}</td><td>any</td><td>replay: the family and the session are
 *       revoked</td></tr>
 *   <tr><td>{@code REVOKED}</td><td>any</td><td>rejected; a revocation is not a theft
 *       signal</td></tr>
 * </table>
 */
public enum RefreshTokenStatus {

    /**
     * The only status that authorises anything. Presenting an active token that has not aged out
     * rotates it.
     */
    ACTIVE,

    /**
     * Already presented once and replaced by a later generation of the same family.
     *
     * <p>This is the status that makes theft detectable: the token is genuine, it is simply no
     * longer the current one. Presenting it again is replay, not a typo, and the family is
     * treated as compromised.
     */
    ROTATED,

    /**
     * Invalidated by a security action, such as a password change or the family revocation
     * that follows a replay.
     */
    REVOKED,

    /**
     * Past {@code expiresAt}.
     *
     * <p>Derived from the clock and never written. See the class documentation for why it is
     * not persisted and how an expired token is actually detected.
     */
    EXPIRED
}
