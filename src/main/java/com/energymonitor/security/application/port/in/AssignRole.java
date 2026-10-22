package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.AssignRoleCommand;

/**
 * Input port for granting a global role to a user.
 */
public interface AssignRole {

    /**
     * @param command the user and the role
     */
    void assign(AssignRoleCommand command);
}