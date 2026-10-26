package com.energymonitor.security.application.usecase;

import com.energymonitor.security.api.AccountRegistered;
import com.energymonitor.security.api.EmailVerificationDeliveryPort;
import com.energymonitor.security.application.exception.InvalidVerificationCodeException;
import com.energymonitor.security.application.port.in.EmailVerification;
import com.energymonitor.security.application.port.out.AccountEventPublisherPort;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.PasswordResetTokenHasherPort;
import com.energymonitor.security.application.port.out.PendingRegistrationPersistencePort;
import com.energymonitor.security.application.port.out.PersonPersistencePort;
import com.energymonitor.security.application.port.out.ResetAttemptLimiterPort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PendingRegistration;
import com.energymonitor.security.domain.model.Person;
import com.energymonitor.security.domain.model.User;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Confirms an email address with a six-digit code, for a registration that is waiting for it or
 * for an account whose address changed.
 *
 * <p>A registration becomes an account here, and only here: the {@code person} and {@code user}
 * rows are created when the code comes back, already verified, and the request is removed. An
 * address nobody reads therefore never leaves an account behind.
 *
 * <p>The code is derived, not stored: it is the peppered HMAC of the account identifier (the one
 * a registration reserves, or the account's own), its address and the current fifteen-minute
 * window, reduced to six digits. A code from the current or the previous window is accepted, so a
 * code is valid for between fifteen and thirty minutes. Nothing needs a table, a code changes by
 * itself when the window moves, and changing the address, or registering again, invalidates it.
 *
 * <p>Six digits are only safe while guessing is bounded. Besides the per-caller limit charged by
 * the controller, every attempt is charged against the address here, so spreading guesses over many
 * callers does not help either.
 */
public class EmailVerificationService implements EmailVerification {

    private static final Logger LOG = LoggerFactory.getLogger(EmailVerificationService.class);

    /** How long one code window lasts. */
    static final Duration WINDOW = Duration.ofMinutes(15);

    /**
     * Separates these digests from password-reset hashes made with the same pepper: a reset code
     * is hashed as {@code idUser:digits}, which can never start with this prefix.
     */
    private static final String PURPOSE = "email-verification:";

    private final UserPersistencePort users;
    private final PendingRegistrationPersistencePort registrations;
    private final PersonPersistencePort persons;
    private final AuditLogPersistencePort audits;
    private final AccountEventPublisherPort events;
    private final IdentifierGeneratorPort identifiers;
    private final PasswordResetTokenHasherPort hasher;
    private final EmailVerificationDeliveryPort delivery;
    private final ResetAttemptLimiterPort perAddressLimiter;
    private final Clock clock;

    public EmailVerificationService(UserPersistencePort users,
                                    PendingRegistrationPersistencePort registrations,
                                    PersonPersistencePort persons, AuditLogPersistencePort audits,
                                    AccountEventPublisherPort events,
                                    IdentifierGeneratorPort identifiers,
                                    PasswordResetTokenHasherPort hasher,
                                    EmailVerificationDeliveryPort delivery,
                                    ResetAttemptLimiterPort perAddressLimiter, Clock clock) {
        this.users = users;
        this.registrations = registrations;
        this.persons = persons;
        this.audits = audits;
        this.events = events;
        this.identifiers = identifiers;
        this.hasher = hasher;
        this.delivery = delivery;
        this.perAddressLimiter = perAddressLimiter;
        this.clock = clock;
    }

    @Override
    public void sendCode(String email) {
        Email address = Email.of(email);
        Instant now = clock.instant();
        String idUser;
        Optional<User> account = users.findActiveByEmail(address);
        if (account.isPresent()) {
            if (account.get().isEmailVerified()) {
                return;
            }
            idUser = account.get().idUser();
        } else {
            Optional<PendingRegistration> pending = waiting(address, now);
            if (pending.isEmpty()) {
                return;
            }
            idUser = pending.get().idUser();
        }
        long window = windowOf(now);
        Instant validUntil = Instant.ofEpochSecond((window + 2) * WINDOW.toSeconds());
        try {
            delivery.deliver(idUser, address.value(), codeFor(idUser, address, window), validUntil);
        } catch (RuntimeException undeliverable) {
            LOG.warn("The verification code for {} could not be delivered", idUser, undeliverable);
        }
    }

    @Override
    public void verify(String email, String code) {
        Email address = Email.of(email);
        perAddressLimiter.checkAllowed(address.value());
        Instant now = clock.instant();

        // An account with the address wins: it is the email change of an existing account, or a
        // Google sign-in created the account meanwhile and the request is left over.
        Optional<User> account = users.findActiveByEmail(address);
        if (account.isPresent()) {
            registrations.findByEmail(address)
                    .ifPresent(leftOver -> registrations.delete(leftOver.idUser()));
            User user = account.get();
            requireCode(code, user.idUser(), address, now);
            if (!user.isEmailVerified()) {
                user.verifyEmail();
                users.save(user);
            }
            return;
        }

        PendingRegistration pending = waiting(address, now).orElseThrow(EmailVerificationService::invalid);
        requireCode(code, pending.idUser(), address, now);
        createAccount(pending, now);
    }

    /** The request becomes the person and the account, verified, and is then forgotten. */
    private void createAccount(PendingRegistration pending, Instant now) {
        Person person = persons.save(pending.toPerson(identifiers.generate()));
        User user = users.save(pending.toUser(person, now));
        audits.save(new AuditLog(identifiers.generate(), user.idUser(), AuditAction.CREATE, null,
                pending.ipAddress().orElse(null), null, now));
        events.accountRegistered(new AccountRegistered(user.idUser(), user.email().value(), now));
        registrations.delete(pending.idUser());
    }

    /** The request for the address, unless it already expired (then it is removed on the way). */
    private Optional<PendingRegistration> waiting(Email address, Instant now) {
        Optional<PendingRegistration> pending = registrations.findByEmail(address);
        if (pending.isPresent() && pending.get().isExpiredAt(now)) {
            registrations.delete(pending.get().idUser());
            return Optional.empty();
        }
        return pending;
    }

    private void requireCode(String code, String idUser, Email address, Instant now) {
        long window = windowOf(now);
        if (!matches(code, codeFor(idUser, address, window))
                && !matches(code, codeFor(idUser, address, window - 1))) {
            throw invalid();
        }
    }

    private static long windowOf(Instant instant) {
        return instant.getEpochSecond() / WINDOW.toSeconds();
    }

    private String codeFor(String idUser, Email address, long window) {
        String digest = hasher.hash(idUser, PURPOSE + address.value() + ":" + window);
        // 48 bits of the digest reduced modulo a million: the bias is below one in 10^8.
        return "%06d".formatted(Long.parseLong(digest.substring(0, 12), 16) % 1_000_000);
    }

    /** Constant time, so the comparison does not leak how many leading digits were right. */
    private static boolean matches(String presented, String expected) {
        return presented != null && MessageDigest.isEqual(
                presented.getBytes(StandardCharsets.UTF_8), expected.getBytes(StandardCharsets.UTF_8));
    }

    private static InvalidVerificationCodeException invalid() {
        return new InvalidVerificationCodeException("The verification code is invalid or expired.");
    }
}
