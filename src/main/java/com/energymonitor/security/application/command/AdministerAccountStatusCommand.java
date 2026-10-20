package com.energymonitor.security.application.command;

import com.energymonitor.security.domain.model.UserStatus;

/**
 * Input of {@code AdministerUserAccount#changeStatus}: an administrator moves another account
 * to a new state.
 *
 * @param actorId   the administrator, taken from the access token
 * @param idUser    the account being changed
 * @param newStatus the target state
 * @param ipAddress optional origin of the request, recorded in the audit trail
 */
public record AdministerAccountStatusCommand(String actorId, String idUser, UserStatus newStatus,
                                             String ipAddress) {
}
