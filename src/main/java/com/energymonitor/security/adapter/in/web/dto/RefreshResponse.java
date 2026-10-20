package com.energymonitor.security.adapter.in.web.dto;

/**
 * Body of a successful refresh: the renewed pair of credentials.
 *
 * <p>Field names match {@link LoginResponse} so a client reuses one shape for both. The
 * account is deliberately absent: this endpoint renews credentials and has no account business
 * to report, so returning one would widen the response for no gain.
 *
 * <p>What is here is exactly the two secrets the client must hold, and nothing about how they
 * are stored. The refresh token is the raw value generated for this rotation; its hash stays in
 * the database and is never part of a response. No lineage, no session identifier and no
 * internal state is exposed.
 *
 * @param accessToken  the newly signed JWT to send as {@code Authorization: Bearer <token>}
 * @param refreshToken the newly generated secret, to be presented at the next refresh
 */
public record RefreshResponse(String accessToken, String refreshToken) {
}
