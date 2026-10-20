package com.energymonitor.security.application.command;

/**
 * Input of {@code LogoutUserSession}: terminates an authenticated session.
 *
 * @param idUserSession the session to close
 * @param idUser        the account the session belongs to, kept for the audit trail
 * @param ipAddress     optional origin of the request, recorded in the audit trail
 */
public record LogoutUserSessionCommand(String idUserSession, String idUser, String ipAddress) {
}
