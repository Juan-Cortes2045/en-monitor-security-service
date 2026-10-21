package com.energymonitor.security.application.usecase;

import com.energymonitor.security.api.AccountDeleted;
import com.energymonitor.security.application.command.DeleteAccountCommand;
import com.energymonitor.security.application.exception.CurrentPasswordMismatchException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.DeleteAccount;
import com.energymonitor.security.application.port.out.AccountDeletionGuardPort;
import com.energymonitor.security.application.port.out.AccountEventPublisherPort;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.PasswordHasherPort;
import com.energymonitor.security.application.port.out.PersonPersistencePort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.application.port.out.UserSessionPersistencePort;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.User;
import java.time.Clock;
import java.time.Instant;

/**
 * Deletes the caller's own account, by soft delete: the rows stay, marked with
 * {@code deleted_at}, so the audit trail keeps pointing at something. The address is released so
 * it can register again.
 *
 * <p>The sessions are closed so no refresh token can mint another access token; the refresh flow
 * also refuses a deleted account on its own. An access token already issued keeps working until it
 * expires, which is at most its fifteen-minute lifetime.
 *
 * <p>energy-monitor-backend is asked first whether the account may go (a sole owner of a home with
 * other members may not), and then hears about the deletion through {@link AccountDeleted} to
 * remove the memberships and homes of the account.
 */
public class DeleteAccountService implements DeleteAccount {

    private final UserPersistencePort userPort;
    private final PersonPersistencePort personPort;
    private final UserSessionPersistencePort sessionPort;
    private final PasswordHasherPort passwordHasher;
    private final AuditLogPersistencePort auditLogPort;
    private final AccountEventPublisherPort events;
    private final AccountDeletionGuardPort deletionGuard;
    private final IdentifierGeneratorPort identifiers;
    private final Clock clock;

    public DeleteAccountService(UserPersistencePort userPort, PersonPersistencePort personPort,
                                UserSessionPersistencePort sessionPort,
                                PasswordHasherPort passwordHasher,
                                AuditLogPersistencePort auditLogPort,
                                AccountEventPublisherPort events,
                                AccountDeletionGuardPort deletionGuard,
                                IdentifierGeneratorPort identifiers, Clock clock) {
        this.userPort = userPort;
        this.personPort = personPort;
        this.sessionPort = sessionPort;
        this.passwordHasher = passwordHasher;
        this.auditLogPort = auditLogPort;
        this.events = events;
        this.deletionGuard = deletionGuard;
        this.identifiers = identifiers;
        this.clock = clock;
    }

    @Override
    public void delete(DeleteAccountCommand command) {
        Instant now = clock.instant();
        User user = userPort.findActive(command.idUser())
                .orElseThrow(() -> new UserNotFoundException("no active user " + command.idUser()));
        if (!passwordHasher.matches(command.password(), user.passwordHash())) {
            throw new CurrentPasswordMismatchException("current password does not match");
        }
        // Asked before anything changes: the other services clean up after the AccountDeleted
        // event, too late to refuse, so a refusal has to come now.
        deletionGuard.ensureDeletable(user.idUser());

        sessionPort.listActiveByUser(user.idUser()).forEach(session -> {
            session.close(now);
            sessionPort.save(session);
        });
        userPort.softDelete(user.idUser(), now);
        personPort.softDelete(user.idPerson(), now);
        auditLogPort.save(new AuditLog(identifiers.generate(), user.idUser(), AuditAction.DELETE,
                null, command.ipAddress(), null, now));
        events.accountDeleted(new AccountDeleted(user.idUser(), now));
    }
}
