package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.ResetPasswordCommand;
import com.energymonitor.security.application.exception.InvalidResetTokenException;
import com.energymonitor.security.application.exception.PasswordPolicyViolationException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.ResetPassword;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.PasswordHasherPort;
import com.energymonitor.security.application.port.out.PasswordPolicyPersistencePort;
import com.energymonitor.security.application.port.out.PasswordResetTokenHasherPort;
import com.energymonitor.security.application.port.out.PasswordResetTokenPersistencePort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordPolicy;
import com.energymonitor.security.domain.model.PasswordResetToken;
import com.energymonitor.security.domain.model.User;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * Redeems a password-recovery code and replaces the account password.
 *
 * <p>The code is bound to the account that requested it. That is the point of the whole design: a
 * six-digit code has fewer than a million possibilities, so it cannot carry the security on its
 * own, and the only way a guess can be kept from redeeming a stranger's code is to never compare it
 * against a stranger's code. The address in the request resolves the account, the account's own
 * pending code is the only candidate, and the digest both sides were written with includes the
 * account identifier, so the two cannot even be computed apart.
 *
 * <h2>Why an attempt is reserved before the code is compared</h2>
 *
 * <p>The comparison is reached only once an attempt has been reserved, and the reservation is a
 * single conditional statement that both spends an attempt and reports whether one was available.
 * Reading the count, comparing, and then writing the count back would leave a window wide enough for
 * a burst of requests to all read the same value and all proceed, which is the difference between
 * five attempts per code and five per code per simultaneous caller.
 *
 * <h2>Why every rejection answers the same thing</h2>
 *
 * <p>An unknown address, a code belonging to somebody else, a wrong code, an expired one and an
 * exhausted one all raise {@link InvalidResetTokenException} with the same message, so a caller
 * cannot learn from the response which of them happened, or whether the address is registered at
 * all.
 *
 * <p><strong>That uniformity is about the response, not about the timing.</strong> The path for a
 * real account does more work than the path for an unknown address: it resolves an account, reads
 * its pending code, reserves an attempt against it and writes an audit row, where an unknown
 * address reaches no row it could reserve and no audit entry it could write. The two paths are
 * therefore not the same length.
 *
 * <p>Measured on this flow, the difference was about 45 ms between the two, which is plenty to tell
 * them apart. The per-caller limit is charged by the web adapter before this use case runs, and the
 * request that mints a code is answered before its work starts, which is what closes the window:
 * neither endpoint answers after doing work whose cost depends on the account. What still bounds an
 * attacker is that limit, charged on every attempt whatever the outcome.
 */
public class ResetPasswordService implements ResetPassword {

    /**
     * Identifier hashed against when the address matches no account.
     *
     * <p>Its only purpose is to keep the work done on that path the same in shape as the work done
     * on the others, so a caller cannot tell them apart by how long the answer took. It is not an
     * account and never was: no row is hashed against it, which is what makes the comparison on
     * that path fail.
     */
    private static final String UNKNOWN_ACCOUNT_ID = "use0000000";

    /** The single message every rejection carries, so no case can drift from another. */
    private static final String REJECTED = "the recovery code is invalid or has expired";

    private final UserPersistencePort userPort;
    private final PasswordResetTokenPersistencePort tokenPort;
    private final PasswordResetTokenHasherPort hasher;
    private final PasswordHasherPort passwordHasher;
    private final PasswordPolicyPersistencePort passwordPolicyPort;
    private final AuditLogPersistencePort auditLogPort;
    private final IdentifierGeneratorPort identifiers;
    private final Clock clock;

    public ResetPasswordService(UserPersistencePort userPort,
                                PasswordResetTokenPersistencePort tokenPort,
                                PasswordResetTokenHasherPort hasher,
                                PasswordHasherPort passwordHasher,
                                PasswordPolicyPersistencePort passwordPolicyPort,
                                AuditLogPersistencePort auditLogPort,
                                IdentifierGeneratorPort identifiers, Clock clock) {
        this.userPort = userPort;
        this.tokenPort = tokenPort;
        this.hasher = hasher;
        this.passwordHasher = passwordHasher;
        this.passwordPolicyPort = passwordPolicyPort;
        this.auditLogPort = auditLogPort;
        this.identifiers = identifiers;
        this.clock = clock;
    }

    @Override
    public void reset(ResetPasswordCommand command) {
        Instant now = clock.instant();

        Optional<User> account = userPort.findActiveByEmail(Email.of(command.email()));
        String idForDigest = account.map(User::idUser).orElse(UNKNOWN_ACCOUNT_ID);

        // Computed whether or not the account is real, so the unknown-address path does not
        // short-circuit into doing no work at all.
        byte[] presented = hasher.hash(idForDigest, command.resetToken())
                .getBytes(StandardCharsets.US_ASCII);

        PasswordResetToken token = account
                .flatMap(user -> latestPendingCode(user.idUser()))
                .orElseThrow(this::reject);

        // The reservation decides whether this request may compare at all. Spending it here means a
        // correct code presented after five wrong ones is refused, which is what a caller expects
        // from a code they cannot guess the rest of, and it bounds the comparisons to five per code
        // however many requests arrive at once.
        if (!tokenPort.reserveAttempt(token.idResetToken())) {
            throw reject();
        }

        // Constant time so that a caller cannot learn the stored digest one character at a time
        // from how long the rejection took.
        if (!MessageDigest.isEqual(presented, token.resetTokenHash().getBytes(StandardCharsets.US_ASCII))) {
            throw reject();
        }

        if (!token.isValid(now)) {
            throw reject();
        }

        PasswordPolicy policy = passwordPolicyPort.activePolicy()
                .orElseThrow(() -> new IllegalStateException("no active password policy is configured"));
        if (!policy.isSatisfiedBy(command.newPassword())) {
            throw new PasswordPolicyViolationException("password does not satisfy the configured policy");
        }
        User user = userPort.findActive(token.idUser())
                .orElseThrow(() -> new UserNotFoundException("no active user " + token.idUser()));

        user.changePassword(passwordHasher.hash(command.newPassword()));
        userPort.save(user);

        // Conditional: if two requests both reach this point with the same code, exactly one is told
        // it redeemed, and the other learns only that the code is gone.
        if (!tokenPort.markUsedIfPending(token.idResetToken())) {
            throw reject();
        }

        auditLogPort.save(new AuditLog(identifiers.generate(), user.idUser(), AuditAction.UPDATE,
                null, command.ipAddress(), null, now));
    }

    /**
     * The most recent code still awaiting redemption for an account, if there is one.
     *
     * <p>Issuing a code consumes the previous ones, so normally there is a single candidate. The
     * scan exists so that a row left pending by an earlier version, or by a concurrent issuance,
     * cannot be redeemed after the newer code the owner actually received.
     *
     * @param idUser the account whose codes are examined
     * @return the newest usable code, empty when none is pending
     */
    private Optional<PasswordResetToken> latestPendingCode(String idUser) {
        PasswordResetToken newest = null;
        for (PasswordResetToken candidate : tokenPort.listActiveByUser(idUser)) {
            if (candidate.isUsed() || candidate.isExpired(clock.instant())) {
                continue;
            }
            if (newest == null || candidate.createdAt().isAfter(newest.createdAt())) {
                newest = candidate;
            }
        }
        return Optional.ofNullable(newest);
    }

    private InvalidResetTokenException reject() {
        return new InvalidResetTokenException(REJECTED);
    }
}