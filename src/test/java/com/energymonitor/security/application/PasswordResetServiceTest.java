package com.energymonitor.security.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.command.CreatePasswordResetTokenCommand;
import com.energymonitor.security.application.command.ResetPasswordCommand;
import com.energymonitor.security.application.exception.InvalidResetTokenException;
import com.energymonitor.security.application.exception.PasswordPolicyViolationException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.usecase.CreatePasswordResetTokenService;
import com.energymonitor.security.application.usecase.ResetPasswordService;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.PasswordResetToken;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code CreatePasswordResetToken} and {@code ResetPassword} requirements: a token is valid
 * only once and only within its window, redeeming one replaces the hash, consumes it and
 * audits the change.
 *
 * <p>The secret that leaves the use case and the hash that stays behind are asserted separately,
 * because the whole point of the flow is that they are two different values: what is delivered
 * is usable, what is stored is not.
 */
class PasswordResetServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-03-01T12:00:00Z"), ZoneOffset.UTC);

    private final UseCaseFixtures.FakeUserPersistencePort users = new UseCaseFixtures.FakeUserPersistencePort();
    private final UseCaseFixtures.FakePasswordResetTokenPersistencePort tokens =
            new UseCaseFixtures.FakePasswordResetTokenPersistencePort();
    private final UseCaseFixtures.FakeTokenGeneratorPort tokenGenerator = new UseCaseFixtures.FakeTokenGeneratorPort();
    private final UseCaseFixtures.FakePasswordResetTokenHasherPort tokenHasher =
            new UseCaseFixtures.FakePasswordResetTokenHasherPort();
    private final UseCaseFixtures.FakePasswordResetDeliveryPort delivery =
            new UseCaseFixtures.FakePasswordResetDeliveryPort();
    private final UseCaseFixtures.FakeIdentifierGeneratorPort identifiers =
            new UseCaseFixtures.FakeIdentifierGeneratorPort();
    private final UseCaseFixtures.FakePasswordHasherPort hasher = new UseCaseFixtures.FakePasswordHasherPort();
    private final UseCaseFixtures.FakePasswordPolicyPersistencePort policies =
            new UseCaseFixtures.FakePasswordPolicyPersistencePort();
    private final UseCaseFixtures.FakeAuditLogPersistencePort audits =
            new UseCaseFixtures.FakeAuditLogPersistencePort();
    private final CreatePasswordResetTokenService createToken =
            new CreatePasswordResetTokenService(users, tokens, tokenGenerator, tokenHasher,
                    delivery, identifiers, CLOCK);
    private final ResetPasswordService resetPassword =
            new ResetPasswordService(users, tokens, tokenHasher, hasher, policies, audits,
                    identifiers, CLOCK);

    @Test
    void issuesAShortLivedSingleUseToken() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);

        PasswordResetToken token = createToken.create(new CreatePasswordResetTokenCommand("ada@example.com"));

        assertTrue(token.isValid(CLOCK.instant()));
        assertEquals(CLOCK.instant().plus(Duration.ofMinutes(15)), token.expirationAt());
    }

    @Test
    void issuesASixDigitNumericCode() {
        // The code has to survive being read off a screen and typed back, so its shape is part
        // of the contract: the endpoint validates it as \d{6} before it ever hashes anything.
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);

        PasswordResetToken token = createToken.create(new CreatePasswordResetTokenCommand("ada@example.com"));

        assertTrue(token.clearToken().orElseThrow().matches("\\d{6}"),
                "the delivered code was not six digits");
    }

    @Test
    void supersedesTheCodeTheAccountAlreadyHeld() {
        // One live code per account is what makes the redemption rate limit mean what it says:
        // with several outstanding, the bound on guessing would be multiplied by how many an
        // attacker could first arrange to have.
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        PasswordResetToken first = createToken.create(
                new CreatePasswordResetTokenCommand("ada@example.com"));
        String firstCode = first.clearToken().orElseThrow();

        PasswordResetToken second = createToken.create(
                new CreatePasswordResetTokenCommand("ada@example.com"));

        assertFalse(first.isValid(CLOCK.instant()), "the superseded code was still redeemable");
        assertTrue(second.isValid(CLOCK.instant()));
        assertNotEquals(firstCode, second.clearToken().orElseThrow());
    }

    @Test
    void leavesAnotherAccountsCodeAlone() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        users.seed("use0000002", "per0000002", "grace@example.com", UserStatus.ACTIVE);
        PasswordResetToken ada = createToken.create(
                new CreatePasswordResetTokenCommand("ada@example.com"));

        createToken.create(new CreatePasswordResetTokenCommand("grace@example.com"));

        assertTrue(ada.isValid(CLOCK.instant()),
                "issuing a code for one account consumed another's");
    }

    @Test
    void storesTheHashAndDeliversTheSecret() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);

        PasswordResetToken token = createToken.create(new CreatePasswordResetTokenCommand("ada@example.com"));

        String clearToken = token.clearToken().orElseThrow();
        assertNotEquals(clearToken, token.resetTokenHash(), "The stored value must not be the secret");
        // What the store is keyed by is the hash, and the delivered value is what redeems it.
        assertEquals(token, tokens.findActiveByHash(tokenHasher.hash("use0000001", clearToken)).orElseThrow());
        var sent = delivery.deliveries().getFirst();
        assertEquals(clearToken, sent.clearToken());
        assertEquals("ada@example.com", sent.recipient());
        assertEquals(token.expirationAt(), sent.validUntil());
        // The channel is told which account and which token the message is about, so it can record
        // the source without this module handing it anything from its own domain.
        assertEquals("use0000001", sent.userId());
        assertEquals(token.idResetToken(), sent.idResetToken());
    }

    @Test
    void aSecretIsNeverDeliveredToAnUnknownAccount() {
        // Nothing is minted, so nothing can be delivered: that is what keeps the acknowledgement
        // outside the controller from meaning anything about registration.
        assertThrows(UserNotFoundException.class,
                () -> createToken.create(new CreatePasswordResetTokenCommand("nobody@example.com")));

        assertTrue(delivery.deliveries().isEmpty());
    }

    @Test
    void anUndeliverableChannelDoesNotFailTheRequest() {
        // The endpoint answers 202 either way; a transport failure escaping here would make the
        // difference observable and turn an outage into an account-enumeration oracle.
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        delivery.failWith(new IllegalStateException("mail gateway unreachable"));

        PasswordResetToken token = createToken.create(new CreatePasswordResetTokenCommand("ada@example.com"));

        assertTrue(token.isValid(CLOCK.instant()));
        assertEquals(token, tokens.findActiveByHash(token.resetTokenHash()).orElseThrow());
    }

    @Test
    void redeemingValidTokenReplacesTheHashAndConsumesIt() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        PasswordResetToken token = createToken.create(new CreatePasswordResetTokenCommand("ada@example.com"));
        String clearToken = token.clearToken().orElseThrow();

        resetPassword.reset(new ResetPasswordCommand("ada@example.com", clearToken, "NewStrong1!", "10.0.0.4"));

        assertTrue(hasher.matches("NewStrong1!", users.findActive("use0000001").orElseThrow().passwordHash()));
        assertTrue(tokens.findActiveByHash(tokenHasher.hash("use0000001", clearToken)).orElseThrow().isUsed());
        assertEquals(AuditAction.UPDATE, audits.logs().getFirst().action());
    }

    @Test
    void abandonsTheAccountWhenTheTokenIsUnknown() {
        assertThrows(InvalidResetTokenException.class,
                () -> resetPassword.reset(new ResetPasswordCommand("ada@example.com", "ghost", "NewStrong1!", null)));
    }

    @Test
    void abandonsTheAccountWhenTheTokenHasExpired() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        Instant now = CLOCK.instant();
        tokens.store(PasswordResetToken.rehydrate("tok0000001", "use0000001",
                tokenHasher.hash("use0000001", "stale-token"), now.minus(Duration.ofHours(1)),
                now.minus(Duration.ofMinutes(30)), false, 0));

        assertThrows(InvalidResetTokenException.class,
                () -> resetPassword.reset(new ResetPasswordCommand("ada@example.com", "stale-token", "NewStrong1!", null)));
    }

    @Test
    void abandonsTheAccountWhenTheTokenWasAlreadyUsed() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        Instant now = CLOCK.instant();
        tokens.store(PasswordResetToken.rehydrate("tok0000001", "use0000001",
                tokenHasher.hash("use0000001", "used-token"), now.minus(Duration.ofMinutes(10)),
                now.plus(Duration.ofMinutes(20)), true, 0));

        assertThrows(InvalidResetTokenException.class,
                () -> resetPassword.reset(new ResetPasswordCommand("ada@example.com", "used-token", "NewStrong1!", null)));
    }

    @Test
    void rejectsNewPasswordBelowPolicyBeforeConsumingTheToken() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        PasswordResetToken token = createToken.create(new CreatePasswordResetTokenCommand("ada@example.com"));
        String clearToken = token.clearToken().orElseThrow();

        assertThrows(PasswordPolicyViolationException.class,
                () -> resetPassword.reset(new ResetPasswordCommand("ada@example.com", clearToken, "weak", null)));

        assertTrue(tokens.findActiveByHash(tokenHasher.hash("use0000001", clearToken)).orElseThrow()
                .isValid(CLOCK.instant()));
    }

    @Test
    @DisplayName("a code issued to another account cannot be redeemed, even when it is correct")
    void refusesACodeThatBelongsToSomebodyElse() {
        // The reason the address is in the request and in the digest. Presenting a stranger's valid
        // code while naming this account must fail, because the comparison is against this
        // account's digest and the two are not the same value.
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        users.seed("use0000002", "per0000002", "grace@example.com", UserStatus.ACTIVE);
        Instant now = CLOCK.instant();
        String gracesCode = "246813";
        tokens.store(PasswordResetToken.rehydrate("tok0000002", "use0000002",
                tokenHasher.hash("use0000002", gracesCode), now, now.plus(Duration.ofMinutes(20)),
                false, 0));

        assertThrows(InvalidResetTokenException.class,
                () -> resetPassword.reset(new ResetPasswordCommand("ada@example.com", gracesCode,
                        "NewStrong1!", null)));

        assertFalse(tokens.findActiveByHash(
                tokenHasher.hash("use0000002", gracesCode)).orElseThrow().isUsed(),
                "somebody else's code was consumed");
    }

    @Test
    @DisplayName("the fifth attempt spends the budget and the sixth is refused")
    void refusesOnceTheAttemptBudgetIsSpent() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        PasswordResetToken token = createToken.create(
                new CreatePasswordResetTokenCommand("ada@example.com"));
        String correct = token.clearToken().orElseThrow();

        // Four wrong guesses, all of which are refused but all of which spend an attempt.
        for (int attempt = 1; attempt <= 4; attempt++) {
            assertThrows(InvalidResetTokenException.class,
                    () -> resetPassword.reset(new ResetPasswordCommand("ada@example.com", "000000",
                            "NewStrong1!", null)));
        }

        // The fifth is the last one the code will ever pay for, and the correct code spends it.
        resetPassword.reset(new ResetPasswordCommand("ada@example.com", correct, "NewStrong1!", null));
        assertTrue(tokens.findActiveByHash(
                tokenHasher.hash("use0000001", correct)).orElseThrow().isUsed());

        // A freshly issued code for the same account works again, which is what makes exhaustion a
        // cost to the caller rather than a lockout.
        PasswordResetToken replacement = createToken.create(
                new CreatePasswordResetTokenCommand("ada@example.com"));
        resetPassword.reset(new ResetPasswordCommand("ada@example.com",
                replacement.clearToken().orElseThrow(), "AnotherStrong1!", null));
    }

    @Test
    @DisplayName("an exhausted code is refused even when the code is correct")
    void refusesACorrectCodeOnceTheBudgetIsSpent() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        PasswordResetToken token = createToken.create(
                new CreatePasswordResetTokenCommand("ada@example.com"));
        String correct = token.clearToken().orElseThrow();
        tokens.exhaust(token.idResetToken());

        assertThrows(InvalidResetTokenException.class,
                () -> resetPassword.reset(new ResetPasswordCommand("ada@example.com", correct,
                        "NewStrong1!", null)));
    }

    @Test
    @DisplayName("an unknown address and a wrong code are refused identically")
    void everyRejectionCarriesTheSameMessage() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        createToken.create(new CreatePasswordResetTokenCommand("ada@example.com"));

        String unknownAccount = assertThrows(InvalidResetTokenException.class,
                () -> resetPassword.reset(new ResetPasswordCommand("nobody@example.com", "000000",
                        "NewStrong1!", null))).getMessage();
        String wrongCode = assertThrows(InvalidResetTokenException.class,
                () -> resetPassword.reset(new ResetPasswordCommand("ada@example.com", "000000",
                        "NewStrong1!", null))).getMessage();
        String someoneElses = assertThrows(InvalidResetTokenException.class,
                () -> resetPassword.reset(new ResetPasswordCommand("grace@example.com", "000000",
                        "NewStrong1!", null))).getMessage();

        // If these three ever differ, a caller can learn which addresses are registered.
        assertEquals(unknownAccount, wrongCode);
        assertEquals(unknownAccount, someoneElses);
    }
}
