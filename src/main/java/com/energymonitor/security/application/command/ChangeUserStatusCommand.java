package com.energymonitor.security.application.command;

import com.energymonitor.security.domain.model.UserStatus;

/**
 * Input of {@code ManageUserStatus}: the new account state to apply.
 *
 * @param idUser    the account
 * @param newStatus the target state
 * @param ipAddress optional origin of the request, recorded in the audit trail
 */
public record ChangeUserStatusCommand(String idUser, UserStatus newStatus, String ipAddress) {
}