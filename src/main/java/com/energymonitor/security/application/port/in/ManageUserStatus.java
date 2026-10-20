package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.ChangeUserStatusCommand;
import com.energymonitor.security.domain.model.User;

/**
 * Input port for activating, deactivating or blocking an account.
 */
public interface ManageUserStatus {

    /**
     * Moves an account to the requested state.
     *
     * <p>Repeated transitions are legal and are not rejected: requesting the state an account
     * already holds is persisted and audited like any other change. Note in particular that
     * {@link UserStatus#ACTIVE} invokes {@link User#activate()}, which clears the failed-login
     * counter, so requesting {@code ACTIVE} also resets that counter even when the account is
     * already active. Both behaviours are intentional domain semantics.
     *
     * @param command the target state
     * @return the updated user
     */
    User changeStatus(ChangeUserStatusCommand command);
}