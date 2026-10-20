package com.energymonitor.security.application.command;

/**
 * Deletes the caller's own account.
 *
 * @param idUser    the account, taken from the access token
 * @param password  the current password, confirming the request
 * @param ipAddress the caller's address, for the audit trail
 */
public record DeleteAccountCommand(String idUser, String password, String ipAddress) {
}
