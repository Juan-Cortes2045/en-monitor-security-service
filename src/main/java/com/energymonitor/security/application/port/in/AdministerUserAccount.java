package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.AdministerAccountRoleCommand;
import com.energymonitor.security.application.command.AdministerAccountStatusCommand;

/**
 * Input port for an administrator acting on another account.
 *
 * <p>The filter chain decides who may call each operation ({@code USER.MANAGE} for the status,
 * {@code ROLE.MANAGE} for the roles). This port adds the rules that depend on the target: an
 * administrator never acts on their own account.
 */
public interface AdministerUserAccount {

    /**
     * Moves an account to a new state. Leaving {@code ACTIVE} also revokes its open sessions,
     * so no refresh token can mint another access token.
     *
     * @param command the actor, the target and the new state
     * @throws com.energymonitor.security.application.exception.SelfAdministrationException when
     *         the actor is the target
     * @throws com.energymonitor.security.application.exception.UserNotFoundException when the
     *         target does not exist
     */
    void changeStatus(AdministerAccountStatusCommand command);

    /**
     * Grants a global role. Granting a role already held changes nothing.
     *
     * @param command the actor, the target and the role
     * @throws com.energymonitor.security.application.exception.SelfAdministrationException when
     *         the actor is the target
     * @throws com.energymonitor.security.application.exception.UserNotFoundException when the
     *         target does not exist
     * @throws com.energymonitor.security.application.exception.RoleNotFoundException when no
     *         assignable role carries that name
     */
    void grantRole(AdministerAccountRoleCommand command);

    /**
     * Revokes a global role. Revoking a role not held changes nothing.
     *
     * @param command the actor, the target and the role
     * @throws com.energymonitor.security.application.exception.SelfAdministrationException when
     *         the actor is the target
     * @throws com.energymonitor.security.application.exception.UserNotFoundException when the
     *         target does not exist
     * @throws com.energymonitor.security.application.exception.RoleNotFoundException when no
     *         role carries that name
     */
    void revokeRole(AdministerAccountRoleCommand command);
}
