package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.RevokeRoleCommand;
import com.energymonitor.security.application.exception.RoleNotFoundException;
import com.energymonitor.security.application.port.in.RevokeRole;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.UserSystemRolePersistencePort;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import java.time.Clock;
import java.time.Instant;

/**
 * Removes a global role from a user.
 */
public class RevokeRoleService implements RevokeRole {

    private final UserSystemRolePersistencePort assignmentPort;
    private final AuditLogPersistencePort auditLogPort;
    private final IdentifierGeneratorPort identifiers;
    private final Clock clock;

    public RevokeRoleService(UserSystemRolePersistencePort assignmentPort,
                             AuditLogPersistencePort auditLogPort,
                             IdentifierGeneratorPort identifiers, Clock clock) {
        this.assignmentPort = assignmentPort;
        this.auditLogPort = auditLogPort;
        this.identifiers = identifiers;
        this.clock = clock;
    }

    @Override
    public void revoke(RevokeRoleCommand command) {
        Instant now = clock.instant();
        if (assignmentPort.findActive(command.idUser(), command.idSystemRole()).isEmpty()) {
            throw new RoleNotFoundException(
                    "user " + command.idUser() + " holds no active role " + command.idSystemRole());
        }
        assignmentPort.remove(command.idUser(), command.idSystemRole());
        auditLogPort.save(new AuditLog(identifiers.generate(), command.idUser(), AuditAction.DELETE,
                null, command.ipAddress(), null, now));
    }
}