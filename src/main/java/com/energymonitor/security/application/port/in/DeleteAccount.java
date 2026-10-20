package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.DeleteAccountCommand;

/**
 * Input port for deleting one's own account.
 */
public interface DeleteAccount {

    /**
     * Soft-deletes the account and its person, closes its sessions and announces the deletion so
     * other modules can drop what they keep about it.
     *
     * @param command the account and its current password
     * @throws com.energymonitor.security.application.exception.CurrentPasswordMismatchException
     *         when the password is wrong
     */
    void delete(DeleteAccountCommand command);
}
