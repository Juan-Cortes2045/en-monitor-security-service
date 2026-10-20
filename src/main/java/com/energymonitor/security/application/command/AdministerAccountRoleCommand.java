package com.energymonitor.security.application.command;

/**
 * Input of {@code AdministerUserAccount#grantRole} and {@code #revokeRole}: an administrator
 * changes the global roles of another account.
 *
 * @param actorId   the administrator, taken from the access token
 * @param idUser    the account being changed
 * @param roleName  name of the global role, such as {@code ADMIN}
 * @param ipAddress optional origin of the request, recorded in the audit trail
 */
public record AdministerAccountRoleCommand(String actorId, String idUser, String roleName,
                                           String ipAddress) {
}
