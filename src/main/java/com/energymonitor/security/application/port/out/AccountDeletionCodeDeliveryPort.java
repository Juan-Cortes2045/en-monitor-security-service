package com.energymonitor.security.application.port.out;

import java.time.Instant;

/**
 * Output port for getting the code that confirms the deletion of an account created with Google
 * to that account's address.
 */
public interface AccountDeletionCodeDeliveryPort {

    /**
     * @param userId     the account being deleted
     * @param recipient  its address
     * @param clearCode  the six-digit code, in clear text
     * @param validUntil the latest instant the code is accepted
     * @throws com.energymonitor.security.application.exception.AccountDeletionCodeUnavailableException
     *         while the mail that carries it cannot be delivered
     */
    void deliver(String userId, String recipient, String clearCode, Instant validUntil);
}
