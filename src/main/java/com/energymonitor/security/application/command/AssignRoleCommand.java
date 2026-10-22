package com.energymonitor.security.application.command;

/**
 * Input of {@code AssignRole}: grants a global role to a user.
 *
 * @param idUser       the recipient
 * @param idSystemRole the role to grant
 * @param ipAddress    optional origin of the request, recorded in the audit trail
 */
public record AssignRoleCommand(String idUser, String idSystemRole, String ipAddress) {
}