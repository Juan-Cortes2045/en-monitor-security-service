package com.energymonitor.security.application.port.out;

import com.energymonitor.security.api.AccountDeletionBlockedException;
import com.energymonitor.security.application.exception.AccountDeletionCheckUnavailableException;

/**
 * Output port for asking the services that keep data about an account whether it may be deleted
 * now. Today that is energy-monitor-backend, which refuses while the account is the only owner of
 * a home that still has other members.
 */
public interface AccountDeletionGuardPort {

    /**
     * Returns normally when the account may be deleted.
     *
     * @param idUser the account about to be deleted
     * @throws AccountDeletionBlockedException          when it may not, with a message for the user
     * @throws AccountDeletionCheckUnavailableException when the answer could not be obtained; the
     *                                                  deletion must not go ahead without one
     */
    void ensureDeletable(String idUser);
}
