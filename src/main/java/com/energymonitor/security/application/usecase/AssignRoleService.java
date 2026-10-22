package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.AssignRoleCommand;
import com.energymonitor.security.application.exception.RoleNotFoundException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.AssignRole;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.SystemRolePersistencePort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.application.port.out.UserSystemRolePersistencePort;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.SystemRole;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserSystemRole;
import java.time.Clock;
import java.time.Instant;

/**
 * Grants a global role to a user.
 */
public class AssignRoleService implements AssignRole {

    private final UserPersistencePort userPort;
    private final SystemRolePersistencePort rolePort;
    private final UserSystemRolePersistencePort assignmentPort;
    private final AuditLogPersistencePort auditLogPort;
    private final IdentifierGeneratorPort identifiers;
    private final Clock clock;

    public AssignRoleService(UserPersistencePort userPort, SystemRolePersistencePort rolePort,
                             UserSystemRolePersistencePort assignmentPort,
                             AuditLogPersistencePort auditLogPort,
                             IdentifierGeneratorPort identifiers, Clock clock) {
        this.userPort = userPort;
        this.rolePort = rolePort;
        this.assignmentPort = assignmentPort;
        this.auditLogPort = auditLogPort;
        this.identifiers = identifiers;
        this.clock = clock;
    }

    @Override
    public void assign(AssignRoleCommand command) {
        Instant now = clock.instant();
        User user = userPort.findActive(command.idUser())
                .orElseThrow(() -> new UserNotFoundException("no active user " + command.idUser()));
        SystemRole role = rolePort.findActive(command.idSystemRole())
                .orElseThrow(() -> new RoleNotFoundException("no active role " + command.idSystemRole()));
        if (assignmentPort.findActive(user.idUser(), role.idSystemRole()).isPresent()) {
            return;
        }
        UserSystemRole assignment = UserSystemRole.assign(user, role, now);
        assignmentPort.save(assignment);
        auditLogPort.save(new AuditLog(identifiers.generate(), user.idUser(), AuditAction.CREATE,
                null, command.ipAddress(), null, now));
    }
}