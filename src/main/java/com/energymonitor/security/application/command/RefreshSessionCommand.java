package com.energymonitor.security.application.command;

/**
 * Request to exchange a refresh token for a new set of credentials.
 *
 * @param rawRefreshToken the secret presented by the client, in clear text. It is hashed
 *                        immediately and never stored, logged or placed in a command that
 *                        outlives the request.
 * @param ipAddress       optional origin of the request, recorded in the audit trail
 */
public record RefreshSessionCommand(String rawRefreshToken, String ipAddress) {
}
