package com.energymonitor.security.application.result;

/**
 * What a refresh attempt produced.
 *
 * <p>The new secret and the identity are only present on {@link RefreshStatus#ROTATED}. On a
 * rejection they are {@code null}, and on a detected replay they are {@code null} as well,
 * because the whole point of that branch is that nothing new is handed out.
 *
 * <p>{@link #identity()} is resolved by the use case from the session that owns the presented
 * token, never from anything the caller supplied. That is what makes the access token issued
 * afterwards provably belong to the account that actually holds the session: the delivery
 * layer never looks up a user, and has no way to be pointed at a different one.
 *
 * @param status          how the attempt ended
 * @param rawRefreshToken the replacement secret, {@code null} unless the attempt rotated
 * @param idUserSession   the session the credentials belong to, {@code null} on rejection
 * @param identity        the account behind that session, {@code null} unless the attempt
 *                        rotated
 */
public record RefreshSessionResult(RefreshStatus status, String rawRefreshToken,
                                   String idUserSession, AuthenticatedUser identity) {

    /** @return whether a new secret was issued */
    public boolean issued() {
        return status == RefreshStatus.ROTATED;
    }
}
