package com.energymonitor.security.application.command;

/**
 * Deletes the caller's own account.
 *
 * @param idUser    the account, taken from the access token
 * @param password  the current password, confirming the request of an account that has one
 * @param code      the code mailed to the address, confirming the request of an account created
 *                  with Google (it has no password the person knows)
 * @param ipAddress the caller's address, for the audit trail
 */
public record DeleteAccountCommand(String idUser, String password, String code, String ipAddress) {

    /** A deletion confirmed with the password. */
    public DeleteAccountCommand(String idUser, String password, String ipAddress) {
        this(idUser, password, null, ipAddress);
    }
}
