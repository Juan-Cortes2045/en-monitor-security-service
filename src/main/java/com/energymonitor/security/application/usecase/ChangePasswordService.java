package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.ChangePasswordCommand;
import com.energymonitor.security.application.exception.CurrentPasswordMismatchException;
import com.energymonitor.security.application.exception.PasswordPolicyViolationException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.ChangePassword;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.PasswordHasherPort;
import com.energymonitor.security.application.port.out.PasswordPolicyPersistencePort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.PasswordPolicy;
import com.energymonitor.security.domain.model.User;
import java.time.Clock;
import java.time.Instant;

/**
 * Changes the password of an authenticated account.
 */
public class ChangePasswordService implements ChangePassword {

    private final UserPersistencePort userPort;
    private final PasswordHasherPort passwordHasher;
    private final PasswordPolicyPersistencePort passwordPolicyPort;
    private final AuditLogPersistencePort auditLogPort;
    private final IdentifierGeneratorPort identifiers;
    private final Clock clock;

    public ChangePasswordService(UserPersistencePort userPort, PasswordHasherPort passwordHasher,
                                 PasswordPolicyPersistencePort passwordPolicyPort,
                                 AuditLogPersistencePort auditLogPort,
                                 IdentifierGeneratorPort identifiers, Clock clock) {
        this.userPort = userPort;
        this.passwordHasher = passwordHasher;
        this.passwordPolicyPort = passwordPolicyPort;
        this.auditLogPort = auditLogPort;
        this.identifiers = identifiers;
        this.clock = clock;
    }

    @Override
    public void change(ChangePasswordCommand command) {
        Instant now = clock.instant();
        User user = userPort.findActive(command.idUser())
                .orElseThrow(() -> new UserNotFoundException("no active user " + command.idUser()));
        if (!passwordHasher.matches(command.currentPassword(), user.passwordHash())) {
            throw new CurrentPasswordMismatchException("current password does not match");
        }
        PasswordPolicy policy = passwordPolicyPort.activePolicy()
                .orElseThrow(() -> new IllegalStateException("no active password policy is configured"));
        if (!policy.isSatisfiedBy(command.newPassword())) {
            throw new PasswordPolicyViolationException("password does not satisfy the configured policy");
        }
        user.changePassword(passwordHasher.hash(command.newPassword()));
        userPort.save(user);
        auditLogPort.save(new AuditLog(identifiers.generate(), user.idUser(), AuditAction.UPDATE,
                null, command.ipAddress(), null, now));
    }
}