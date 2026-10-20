package com.energymonitor.security.application.usecase;

import com.energymonitor.security.api.EmailVerificationDeliveryPort;
import com.energymonitor.security.application.exception.InvalidVerificationCodeException;
import com.energymonitor.security.application.port.in.EmailVerification;
import com.energymonitor.security.application.port.out.PasswordResetTokenHasherPort;
import com.energymonitor.security.application.port.out.ResetAttemptLimiterPort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.User;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Confirms that an account owns its email address with a six-digit code.
 *
 * <p>The code is derived, not stored: it is the peppered HMAC of the account, its address and the
 * current fifteen-minute window, reduced to six digits. A code from the current or the previous
 * window is accepted, so a code is valid for between fifteen and thirty minutes. Nothing needs a
 * table, a code changes by itself when the window moves, and changing the address invalidates it.
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
    private final PasswordResetTokenHasherPort hasher;
    private final EmailVerificationDeliveryPort delivery;
    private final ResetAttemptLimiterPort perAddressLimiter;
    private final Clock clock;

    public EmailVerificationService(UserPersistencePort users, PasswordResetTokenHasherPort hasher,
                                    EmailVerificationDeliveryPort delivery,
                                    ResetAttemptLimiterPort perAddressLimiter, Clock clock) {
        this.users = users;
        this.hasher = hasher;
        this.delivery = delivery;
        this.perAddressLimiter = perAddressLimiter;
        this.clock = clock;
    }

    @Override
    public void sendCode(String email) {
        User user = users.findActiveByEmail(Email.of(email)).orElse(null);
        if (user == null || user.isEmailVerified()) {
            return;
        }
        long window = windowOf(clock.instant());
        Instant validUntil = Instant.ofEpochSecond((window + 2) * WINDOW.toSeconds());
        try {
            delivery.deliver(user.idUser(), user.email().value(), codeFor(user, window), validUntil);
        } catch (RuntimeException undeliverable) {
            LOG.warn("The verification code for {} could not be delivered", user.idUser(),
                    undeliverable);
        }
    }

    @Override
    public void verify(String email, String code) {
        Email address = Email.of(email);
        perAddressLimiter.checkAllowed(address.value());
        User user = users.findActiveByEmail(address).orElseThrow(EmailVerificationService::invalid);
        long window = windowOf(clock.instant());
        if (!matches(code, codeFor(user, window)) && !matches(code, codeFor(user, window - 1))) {
            throw invalid();
        }
        if (!user.isEmailVerified()) {
            user.verifyEmail();
            users.save(user);
        }
    }

    private static long windowOf(Instant instant) {
        return instant.getEpochSecond() / WINDOW.toSeconds();
    }

    private String codeFor(User user, long window) {
        String digest = hasher.hash(user.idUser(), PURPOSE + user.email().value() + ":" + window);
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
