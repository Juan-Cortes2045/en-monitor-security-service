package com.energymonitor.security.application.port.out;

import com.energymonitor.security.api.AccountAdministered;
import com.energymonitor.security.api.AccountDeleted;
import com.energymonitor.security.api.AccountRegistered;

/**
 * Output port for telling other modules about account lifecycle changes.
 */
public interface AccountEventPublisherPort {

    /**
     * @param event the deletion that just happened
     */
    void accountDeleted(AccountDeleted event);

    /**
     * @param event the account that was just created
     */
    void accountRegistered(AccountRegistered event);

    /**
     * @param event the change an administrator just made to another account
     */
    void accountAdministered(AccountAdministered event);
}
