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
     * <p>An account with a password confirms with it; an account created with Google confirms
     * with the code sent by {@link #sendDeletionCode}.
     *
     * @param command the account and its password or code
     * @throws com.energymonitor.security.application.exception.CurrentPasswordMismatchException
     *         when the password is wrong
     * @throws com.energymonitor.security.application.exception.InvalidVerificationCodeException
     *         when the code is wrong or expired
     */
    void delete(DeleteAccountCommand command);

    /**
     * Mails the code that confirms the deletion of an account created with Google.
     *
     * @param idUser the account, taken from the access token
     * @throws com.energymonitor.security.application.exception.DeletionCodeNotApplicableException
     *         when the account has a password, which is what confirms its deletion
     * @throws com.energymonitor.security.application.exception.AccountDeletionCodeUnavailableException
     *         while the mail that carries the code cannot be delivered
     */
    void sendDeletionCode(String idUser);
}
