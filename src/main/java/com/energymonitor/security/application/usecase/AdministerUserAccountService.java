package com.energymonitor.security.application.usecase;

import com.energymonitor.security.api.AccountAdministered;
import com.energymonitor.security.application.command.AdministerAccountRoleCommand;
import com.energymonitor.security.application.command.AdministerAccountStatusCommand;
import com.energymonitor.security.application.command.AssignRoleCommand;
import com.energymonitor.security.application.command.ChangeUserStatusCommand;
import com.energymonitor.security.application.command.RevokeRoleCommand;
import com.energymonitor.security.application.exception.RoleNotFoundException;
import com.energymonitor.security.application.exception.SelfAdministrationException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.AdministerUserAccount;
import com.energymonitor.security.application.port.in.AssignRole;
import com.energymonitor.security.application.port.in.ManageUserStatus;
import com.energymonitor.security.application.port.in.RevokeRole;
import com.energymonitor.security.application.port.out.AccountEventPublisherPort;
import com.energymonitor.security.application.port.out.SystemRolePersistencePort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.application.port.out.UserSessionPersistencePort;
import com.energymonitor.security.application.port.out.UserSystemRolePersistencePort;
import com.energymonitor.security.domain.model.RevocationReason;
import com.energymonitor.security.domain.model.SystemRole;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Instant;

/**
 * An administrator acting on another account.
 *
 * <p>The state change, the grant and the revocation themselves, with their audit rows, are the
 * existing {@link ManageUserStatus}, {@link AssignRole} and {@link RevokeRole} use cases. This
 * service adds what they cannot know because they are not told who is asking: the actor never
 * acts on their own account, roles are named rather than identified, an account that stops
 * being active loses its open sessions, and every real change is published as
 * {@link AccountAdministered} so the other administrators are told about it.
 */
public class AdministerUserAccountService implements AdministerUserAccount {

    private final UserPersistencePort userPort;
    private final SystemRolePersistencePort rolePort;
    private final UserSystemRolePersistencePort assignmentPort;
    private final UserSessionPersistencePort sessionPort;
    private final ManageUserStatus manageUserStatus;
    private final AssignRole assignRole;
    private final RevokeRole revokeRole;
    private final AccountEventPublisherPort events;
    private final Clock clock;

    public AdministerUserAccountService(UserPersistencePort userPort,
                                        SystemRolePersistencePort rolePort,
                                        UserSystemRolePersistencePort assignmentPort,
                                        UserSessionPersistencePort sessionPort,
                                        ManageUserStatus manageUserStatus, AssignRole assignRole,
                                        RevokeRole revokeRole, AccountEventPublisherPort events,
                                        Clock clock) {
        this.userPort = userPort;
        this.rolePort = rolePort;
        this.assignmentPort = assignmentPort;
        this.sessionPort = sessionPort;
        this.manageUserStatus = manageUserStatus;
        this.assignRole = assignRole;
        this.revokeRole = revokeRole;
        this.events = events;
        this.clock = clock;
    }

    @Override
    public void changeStatus(AdministerAccountStatusCommand command) {
        refuseSelf(command.actorId(), command.idUser());
        UserStatus previous = requireUser(command.idUser()).status();
        manageUserStatus.changeStatus(new ChangeUserStatusCommand(command.idUser(),
                command.newStatus(), command.ipAddress()));
        Instant now = clock.instant();
        if (command.newStatus() != UserStatus.ACTIVE) {
            // The refresh flow already refuses an account that cannot authenticate; revoking the
            // sessions as well leaves no session that looks usable in the audit trail.
            sessionPort.listActiveByUser(command.idUser()).forEach(session -> {
                session.revoke(now, RevocationReason.ADMINISTRATIVE);
                sessionPort.save(session);
            });
        }
        if (previous != command.newStatus()) {
            publish(command.actorId(), command.idUser(), AccountAdministered.Action.STATUS_CHANGED,
                    command.newStatus().name(), now);
        }
    }

    @Override
    public void grantRole(AdministerAccountRoleCommand command) {
        refuseSelf(command.actorId(), command.idUser());
        requireUser(command.idUser());
        SystemRole role = rolePort.findActiveByName(command.roleName())
                .filter(SystemRole::canBeAssigned)
                .orElseThrow(() -> new RoleNotFoundException(
                        "no assignable role " + command.roleName()));
        if (assignmentPort.findActive(command.idUser(), role.idSystemRole()).isPresent()) {
            return;
        }
        assignRole.assign(new AssignRoleCommand(command.idUser(), role.idSystemRole(),
                command.ipAddress()));
        publish(command.actorId(), command.idUser(), AccountAdministered.Action.ROLE_GRANTED,
                role.name(), clock.instant());
    }

    @Override
    public void revokeRole(AdministerAccountRoleCommand command) {
        refuseSelf(command.actorId(), command.idUser());
        requireUser(command.idUser());
        SystemRole role = rolePort.findActiveByName(command.roleName())
                .orElseThrow(() -> new RoleNotFoundException("no role " + command.roleName()));
        if (assignmentPort.findActive(command.idUser(), role.idSystemRole()).isEmpty()) {
            return;
        }
        revokeRole.revoke(new RevokeRoleCommand(command.idUser(), role.idSystemRole(),
                command.ipAddress()));
        publish(command.actorId(), command.idUser(), AccountAdministered.Action.ROLE_REVOKED,
                role.name(), clock.instant());
    }

    private User requireUser(String idUser) {
        return userPort.findActive(idUser)
                .orElseThrow(() -> new UserNotFoundException("no active user " + idUser));
    }

    private void publish(String actorId, String idUser, AccountAdministered.Action action,
                         String detail, Instant now) {
        events.accountAdministered(new AccountAdministered(actorId, idUser, action, detail, now));
    }

    private static void refuseSelf(String actorId, String idUser) {
        if (actorId.equals(idUser)) {
            throw new SelfAdministrationException("an administrator cannot change their own account");
        }
    }
}
