package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.ChangeUserStatusCommand;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.ManageUserStatus;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Instant;

/**
 * Moves an account between {@code ACTIVE}, {@code INACTIVE} and {@code BLOCKED}.
 */
public class ManageUserStatusService implements ManageUserStatus {

    private final UserPersistencePort userPort;
    private final AuditLogPersistencePort auditLogPort;
    private final IdentifierGeneratorPort identifiers;
    private final Clock clock;

    public ManageUserStatusService(UserPersistencePort userPort,
                                   AuditLogPersistencePort auditLogPort,
                                   IdentifierGeneratorPort identifiers, Clock clock) {
        this.userPort = userPort;
        this.auditLogPort = auditLogPort;
        this.identifiers = identifiers;
        this.clock = clock;
    }

    @Override
    public User changeStatus(ChangeUserStatusCommand command) {
        Instant now = clock.instant();
        User user = userPort.findActive(command.idUser())
                .orElseThrow(() -> new UserNotFoundException("no active user " + command.idUser()));
        switch (command.newStatus()) {
            case ACTIVE -> user.activate();
            case INACTIVE -> user.deactivate();
            case BLOCKED -> user.block();
        }
        userPort.save(user);
        auditLogPort.save(new AuditLog(identifiers.generate(), user.idUser(), AuditAction.UPDATE,
                null, command.ipAddress(), null, now));
        return user;
    }
}