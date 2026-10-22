package com.energymonitor.security.application.command;

/**
 * Input of {@code RevokeRole}: removes a global role from a user.
 *
 * @param idUser       the recipient
 * @param idSystemRole the role to revoke
 * @param ipAddress    optional origin of the request, recorded in the audit trail
 */
public record RevokeRoleCommand(String idUser, String idSystemRole, String ipAddress) {
}