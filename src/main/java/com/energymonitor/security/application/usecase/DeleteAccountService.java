package com.energymonitor.security.application.usecase;

import com.energymonitor.security.api.AccountDeleted;
import com.energymonitor.security.application.command.DeleteAccountCommand;
import com.energymonitor.security.application.exception.CurrentPasswordMismatchException;
import com.energymonitor.security.application.exception.DeletionCodeNotApplicableException;
import com.energymonitor.security.application.exception.InvalidVerificationCodeException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.DeleteAccount;
import com.energymonitor.security.application.port.out.AccountDeletionCodeDeliveryPort;
import com.energymonitor.security.application.port.out.AccountDeletionGuardPort;
import com.energymonitor.security.application.port.out.AccountEventPublisherPort;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.PasswordHasherPort;
import com.energymonitor.security.application.port.out.PasswordResetTokenHasherPort;
import com.energymonitor.security.application.port.out.PersonPersistencePort;
import com.energymonitor.security.application.port.out.ResetAttemptLimiterPort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.application.port.out.UserSessionPersistencePort;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.User;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
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
 *
 * <p>An account with a password confirms with it. An account created with Google has none the
 * person knows, so it confirms with a six-digit code mailed to its address. The code is derived,
 * not stored, like the verification code: the peppered HMAC of the account, its address and the
 * fifteen-minute window, accepted in its window and the next one. Its purpose prefix keeps it
 * apart from the verification and recovery codes made with the same pepper, and guesses are
 * bounded per account.
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
    private final PasswordResetTokenHasherPort codeHasher;
    private final AccountDeletionCodeDeliveryPort codeDelivery;
    private final ResetAttemptLimiterPort codeAttempts;
    private final Clock clock;

    /** How long one code window lasts. */
    static final Duration WINDOW = Duration.ofMinutes(15);

    /** Separates these digests from the verification and recovery ones made with the same pepper. */
    private static final String PURPOSE = "account-deletion:";

    public DeleteAccountService(UserPersistencePort userPort, PersonPersistencePort personPort,
                                UserSessionPersistencePort sessionPort,
                                PasswordHasherPort passwordHasher,
                                AuditLogPersistencePort auditLogPort,
                                AccountEventPublisherPort events,
                                AccountDeletionGuardPort deletionGuard,
                                IdentifierGeneratorPort identifiers,
                                PasswordResetTokenHasherPort codeHasher,
                                AccountDeletionCodeDeliveryPort codeDelivery,
                                ResetAttemptLimiterPort codeAttempts, Clock clock) {
        this.userPort = userPort;
        this.personPort = personPort;
        this.sessionPort = sessionPort;
        this.passwordHasher = passwordHasher;
        this.auditLogPort = auditLogPort;
        this.events = events;
        this.deletionGuard = deletionGuard;
        this.identifiers = identifiers;
        this.codeHasher = codeHasher;
        this.codeDelivery = codeDelivery;
        this.codeAttempts = codeAttempts;
        this.clock = clock;
    }

    @Override
    public void delete(DeleteAccountCommand command) {
        Instant now = clock.instant();
        User user = userPort.findActive(command.idUser())
                .orElseThrow(() -> new UserNotFoundException("no active user " + command.idUser()));
        if (user.isGoogleAccount()) {
            requireDeletionCode(user, command.code(), now);
        } else if (command.password() == null
                || !passwordHasher.matches(command.password(), user.passwordHash())) {
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

    @Override
    public void sendDeletionCode(String idUser) {
        User user = userPort.findActive(idUser)
                .orElseThrow(() -> new UserNotFoundException("no active user " + idUser));
        if (!user.isGoogleAccount()) {
            throw new DeletionCodeNotApplicableException(
                    "This account confirms its deletion with its password.");
        }
        long window = windowOf(clock.instant());
        Instant validUntil = Instant.ofEpochSecond((window + 2) * WINDOW.toSeconds());
        codeDelivery.deliver(user.idUser(), user.email().value(), codeFor(user, window), validUntil);
    }

    private void requireDeletionCode(User user, String code, Instant now) {
        codeAttempts.checkAllowed(user.idUser());
        long window = windowOf(now);
        if (!matches(code, codeFor(user, window)) && !matches(code, codeFor(user, window - 1))) {
            throw new InvalidVerificationCodeException("The deletion code is invalid or expired.");
        }
    }

    private static long windowOf(Instant instant) {
        return instant.getEpochSecond() / WINDOW.toSeconds();
    }

    private String codeFor(User user, long window) {
        String digest = codeHasher.hash(user.idUser(), PURPOSE + user.email().value() + ":" + window);
        // 48 bits of the digest reduced modulo a million: the bias is below one in 10^8.
        return "%06d".formatted(Long.parseLong(digest.substring(0, 12), 16) % 1_000_000);
    }

    /** Constant time, so the comparison does not leak how many leading digits were right. */
    private static boolean matches(String presented, String expected) {
        return presented != null && MessageDigest.isEqual(
                presented.getBytes(StandardCharsets.UTF_8), expected.getBytes(StandardCharsets.UTF_8));
    }
}
