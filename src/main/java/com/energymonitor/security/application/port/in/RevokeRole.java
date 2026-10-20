package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.RevokeRoleCommand;

/**
 * Input port for removing a global role from a user.
 */
public interface RevokeRole {

    /**
     * @param command the user and the role
     */
    void revoke(RevokeRoleCommand command);
}