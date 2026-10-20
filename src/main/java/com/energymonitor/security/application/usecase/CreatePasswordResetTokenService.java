package com.energymonitor.security.application.usecase;

import com.energymonitor.security.api.PasswordResetDeliveryPort;
import com.energymonitor.security.application.command.CreatePasswordResetTokenCommand;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.CreatePasswordResetToken;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.PasswordResetTokenHasherPort;
import com.energymonitor.security.application.port.out.PasswordResetTokenPersistencePort;
import com.energymonitor.security.application.port.out.TokenGeneratorPort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordResetToken;
import com.energymonitor.security.domain.model.User;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;

/**
 * Issues a short-lived, single-use password-recovery code and puts it on its way to its owner.
 *
 * <h2>The secret exists twice, and only ever as a hash in between</h2>
 *
 * <p>A clear code is generated here, hashed immediately with the configured pepper, and stored as
 * the hash. The clear value leaves this method exactly once, through
 * {@link PasswordResetDeliveryPort}, which is the only channel entitled to carry it. Nothing here
 * returns it to a caller that could serialise it: the use case does hand the token object back to
 * the web adapter, and that object still carries the code in memory, but no response DTO is built
 * from it and no field of it is persisted.
 *
 * <h2>Why the code is six digits, and what that obliges</h2>
 *
 * <p>A code has to be read off a screen by a person and typed back, which is the reason it is
 * short. That leaves about twenty bits, which is too few to be a defence on its own: anyone
 * holding the table could recompute every candidate. Two other decisions carry the weight instead,
 * and this class is where the second of them happens.
 *
 * <p>First, the stored value is {@code HMAC-SHA256(code, pepper)}. Deterministic, so redemption
 * can resolve a code to its row by hashing it, and peppered, so a copy of the table is not enough
 * to recover a code.
 *
 * <p>Second, this class consumes the codes the account already held. One live code per account
 * means the per-caller rate limit on redemption is the real bound on guessing, instead of that
 * bound multiplied by the number of codes an attacker could first arrange to have outstanding.
 *
 * <h2>Why delivery failures do not fail the request</h2>
 *
 * <p>The endpoint that triggers this answers 202 whether or not the account exists. A delivery
 * adapter that let its transport failure escape would therefore change the answer for exactly
 * the addresses that are registered, turning an outage into a way of enumerating them. The
 * failure is logged and swallowed instead: the stored token stays valid, so support can still
 * act on it, and the caller learns nothing beyond the acknowledgement it always gets.
 */
public class CreatePasswordResetTokenService implements CreatePasswordResetToken {

    private static final Logger LOG =
            LoggerFactory.getLogger(CreatePasswordResetTokenService.class);

    /**
     * How many digits a recovery code has.
     *
     * <p>Six is what a person can read off a screen and type back without a transcription error,
     * which is the point: a code nobody can enter correctly saves nobody. Twenty bits is not a
     * defence and is not meant to be one. What defends it is the pepper mixed into the stored
     * digest, which makes an offline attack on the table useless, and the rate limit on
     * redemption, which makes an online attack take years. A code long enough to need neither
     * would be the one thing nobody can type.
     */
    private static final int CODE_DIGITS = 6;

    /** How many times a code is redrawn when the generated value is already on file. */
    private static final int MAX_GENERATION_ATTEMPTS = 5;

    /**
     * How long a code stays redeemable. Shorter than the thirty minutes a long random token could
     * afford, because a code that can be guessed is worth less the longer it waits.
     */
    private static final Duration VALIDITY = Duration.ofMinutes(15);

    private final UserPersistencePort userPort;
    private final PasswordResetTokenPersistencePort tokenPort;
    private final TokenGeneratorPort tokenGenerator;
    private final PasswordResetTokenHasherPort hasher;
    private final PasswordResetDeliveryPort delivery;
    private final IdentifierGeneratorPort identifiers;
    private final Clock clock;

    public CreatePasswordResetTokenService(UserPersistencePort userPort,
                                           PasswordResetTokenPersistencePort tokenPort,
                                           TokenGeneratorPort tokenGenerator,
                                           PasswordResetTokenHasherPort hasher,
                                           PasswordResetDeliveryPort delivery,
                                           IdentifierGeneratorPort identifiers, Clock clock) {
        this.userPort = userPort;
        this.tokenPort = tokenPort;
        this.tokenGenerator = tokenGenerator;
        this.hasher = hasher;
        this.delivery = delivery;
        this.identifiers = identifiers;
        this.clock = clock;
    }

    @Override
    public PasswordResetToken create(CreatePasswordResetTokenCommand command) {
        Instant now = clock.instant();
        User user = userPort.findActiveByEmail(Email.of(command.email()))
                .orElseThrow(() -> new UserNotFoundException("no active account for " + command.email()));

        // Before issuing, not after: any code the account still holds is superseded by this one.
        // Leaving several live at once would let an attacker spend the redemption allowance
        // against all of them, turning a limit of ten into ten times ten.
        int superseded = tokenPort.consumeAllForUser(user.idUser());
        if (superseded > 0) {
            LOG.debug("Superseded {} pending recovery code(s) for {}", superseded, user.idUser());
        }

        return issueAndDeliver(user, now);
    }

    /**
     * Issues the code, retrying a few times if the generated value is already on file.
     *
     * <p>The stored value is unique, so a code that collides with a live one cannot be inserted.
     * With under a million possibilities and codes that expire, that is vanishingly unlikely, but
     * "unlikely" is not "impossible", and the alternative to regenerating is an insert that throws
     * for no reason a user could understand. Each retry is a fresh draw, so this terminates with
     * probability one.
     *
     * <p>The attempt counter is what makes the uniqueness safe to rely on: only the newest code of
     * an account is redeemable, so the row a collision would hit is one nobody can present.
     */
    private PasswordResetToken issueAndDeliver(User user, Instant now) {
        for (int attempt = 1; attempt <= MAX_GENERATION_ATTEMPTS; attempt++) {
            String clearCode = tokenGenerator.generateNumericCode(CODE_DIGITS);
            PasswordResetToken token = PasswordResetToken.issue(identifiers.generate(),
                    user.idUser(), clearCode, hasher.hash(user.idUser(), clearCode), now,
                    now.plus(VALIDITY));
            try {
                PasswordResetToken stored = tokenPort.save(token);
                deliver(user.email(), stored);
                return stored;
            } catch (DataIntegrityViolationException collision) {
                LOG.warn("Regenerated recovery code for {} after a collision on attempt {}",
                        user.idUser(), attempt);
            }
        }
        // Five draws on a collision each is not an outcome worth reporting as a request failure:
        // it means the table holds every one of the codes still live for this account, which the
        // one-code-per-account rule should already prevent.
        throw new IllegalStateException(
                "could not issue a recovery code for " + user.idUser() + " without colliding");
    }

    /**
     * Hands the secret to the delivery channel, if the token still carries it.
     *
     * @param recipient the account that asked for the reset
     * @param token     the stored token, holding the clear secret in memory
     */
    private void deliver(Email recipient, PasswordResetToken token) {
        String clearToken = token.clearToken().orElse(null);
        if (clearToken == null) {
            // The token came back from the store without a secret, so there is nothing to send.
            // Persisting and delivering are separate concerns and this must not fail the flow.
            LOG.warn("The stored password reset token {} carries no secret to deliver",
                    token.idResetToken());
            return;
        }
        try {
            delivery.deliver(token.idUser(), recipient.value(), token.idResetToken(), clearToken,
                    token.expirationAt());
        } catch (RuntimeException undeliverable) {
            // The token identifier, not the address: the row already says whose it is, and an
            // address in a log is personal data with a much longer life than this failure has.
            LOG.warn("The password reset token {} could not be delivered", token.idResetToken(),
                    undeliverable);
        }
    }
}
