package com.energymonitor.security.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.energymonitor.security.adapter.out.security.InMemoryResetAttemptLimiter;
import com.energymonitor.security.adapter.out.security.PepperedHmacResetCodeHasher;
import com.energymonitor.security.api.AccountRegistered;
import com.energymonitor.security.api.EmailVerificationDeliveryPort;
import com.energymonitor.security.application.exception.InvalidVerificationCodeException;
import com.energymonitor.security.application.exception.TooManyResetAttemptsException;
import com.energymonitor.security.application.usecase.EmailVerificationService;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordHash;
import com.energymonitor.security.domain.model.PendingRegistration;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class EmailVerificationServiceTest {

    private static final Instant NOW = Instant.parse("2026-03-01T12:05:00Z");
    private static final String EMAIL = "ada@example.com";

    private final UseCaseFixtures.FakeUserPersistencePort users =
            new UseCaseFixtures.FakeUserPersistencePort();
    private final PepperedHmacResetCodeHasher hasher =
            new PepperedHmacResetCodeHasher("test-pepper-of-sufficient-length-0123");
    private final RecordingDelivery delivery = new RecordingDelivery();
    private final UseCaseFixtures.FakePendingRegistrationPersistencePort pending =
            new UseCaseFixtures.FakePendingRegistrationPersistencePort();
    private final UseCaseFixtures.FakePersonPersistencePort persons =
            new UseCaseFixtures.FakePersonPersistencePort();
    private final UseCaseFixtures.FakeAuditLogPersistencePort audits =
            new UseCaseFixtures.FakeAuditLogPersistencePort();
    private final UseCaseFixtures.FakeAccountEventPublisherPort events =
            new UseCaseFixtures.FakeAccountEventPublisherPort();
    private final UseCaseFixtures.FakeIdentifierGeneratorPort identifiers =
            new UseCaseFixtures.FakeIdentifierGeneratorPort();

    private EmailVerificationService serviceAt(Instant instant) {
        Clock clock = Clock.fixed(instant, ZoneOffset.UTC);
        return new EmailVerificationService(users, pending, persons, audits, events, identifiers,
                hasher, delivery, new InMemoryResetAttemptLimiter(5, Duration.ofMinutes(15), clock),
                clock);
    }

    private PendingRegistration registered(Instant at) {
        return pending.save(PendingRegistration.request("use0000009", Email.of(EMAIL), "Ada",
                "Lovelace", PasswordHash.of("hash:secret"), null, "10.0.0.7", at));
    }

    private User unverified() {
        return users.save(User.register("use0000001", "per0000001", PasswordHash.of("hash"),
                Email.of(EMAIL), UseCaseFixtures.REGISTRATION, null));
    }

    private String sentCode() {
        serviceAt(NOW).sendCode(EMAIL);
        return delivery.sent.isEmpty() ? null : delivery.sent.getLast().clearCode();
    }

    @Test
    @DisplayName("sends a six-digit code that is valid for at least fifteen minutes")
    void sendsASixDigitCode() {
        unverified();

        serviceAt(NOW).sendCode(EMAIL);

        assertThat(delivery.sent).hasSize(1);
        Sent sent = delivery.sent.getFirst();
        assertThat(sent.clearCode()).matches("\\d{6}");
        assertThat(sent.recipient()).isEqualTo(EMAIL);
        assertThat(sent.validUntil()).isAfterOrEqualTo(NOW.plus(Duration.ofMinutes(15)));
    }

    @Test
    @DisplayName("sends nothing for an unknown or an already verified address")
    void sendsNothingWhenThereIsNothingToVerify() {
        serviceAt(NOW).sendCode("nobody@example.com");
        users.seed("use0000002", "per0000002", "grace@example.com", UserStatus.ACTIVE);
        serviceAt(NOW).sendCode("grace@example.com");

        assertThat(delivery.sent).isEmpty();
    }

    @Test
    @DisplayName("the code that was sent verifies the address")
    void theSentCodeVerifies() {
        unverified();

        serviceAt(NOW).verify(EMAIL, sentCode());

        assertThat(users.findActive("use0000001").orElseThrow().isEmailVerified()).isTrue();
    }

    @Test
    @DisplayName("a code is still accepted during the next window and refused after it")
    void aCodeExpiresAfterTheNextWindow() {
        unverified();
        String code = sentCode();

        serviceAt(NOW.plus(Duration.ofMinutes(15))).verify(EMAIL, code);
        assertThat(users.findActive("use0000001").orElseThrow().isEmailVerified()).isTrue();

        assertThatThrownBy(() -> serviceAt(NOW.plus(Duration.ofMinutes(30))).verify(EMAIL, code))
                .isInstanceOf(InvalidVerificationCodeException.class);
    }

    @Test
    @DisplayName("a wrong code and an unknown address are refused the same way")
    void wrongCodeAndUnknownAddressLookAlike() {
        unverified();
        String wrong = sentCode().equals("000000") ? "000001" : "000000";

        assertThatThrownBy(() -> serviceAt(NOW).verify(EMAIL, wrong))
                .isInstanceOf(InvalidVerificationCodeException.class)
                .hasMessage("The verification code is invalid or expired.");
        assertThatThrownBy(() -> serviceAt(NOW).verify("nobody@example.com", "123456"))
                .isInstanceOf(InvalidVerificationCodeException.class)
                .hasMessage("The verification code is invalid or expired.");
        assertThat(users.findActive("use0000001").orElseThrow().isEmailVerified()).isFalse();
    }

    @Test
    @DisplayName("guesses are bounded per address, whoever makes them")
    void guessesAreBoundedPerAddress() {
        unverified();
        String code = sentCode();
        String wrong = code.equals("000000") ? "000001" : "000000";
        EmailVerificationService service = serviceAt(NOW);
        for (int attempt = 1; attempt <= 5; attempt++) {
            assertThatThrownBy(() -> service.verify(EMAIL, wrong))
                    .isInstanceOf(InvalidVerificationCodeException.class);
        }

        assertThatThrownBy(() -> service.verify(EMAIL, code))
                .isInstanceOf(TooManyResetAttemptsException.class);
    }

    @Test
    @DisplayName("a registration gets its code at the identifier the account will take")
    void sendsTheCodeOfARegistration() {
        registered(NOW);

        serviceAt(NOW).sendCode(EMAIL);

        assertThat(delivery.sent).singleElement()
                .satisfies(sent -> {
                    assertThat(sent.userId()).isEqualTo("use0000009");
                    assertThat(sent.recipient()).isEqualTo(EMAIL);
                });
    }

    @Test
    @DisplayName("the code of a registration creates the account, verified, and forgets the request")
    void theCodeOfARegistrationCreatesTheAccount() {
        registered(NOW);

        serviceAt(NOW).verify(EMAIL, sentCode());

        User account = users.findActive("use0000009").orElseThrow();
        assertThat(account.email().value()).isEqualTo(EMAIL);
        assertThat(account.isEmailVerified()).isTrue();
        assertThat(account.status()).isEqualTo(UserStatus.ACTIVE);
        assertThat(account.passwordHash()).isEqualTo(PasswordHash.of("hash:secret"));
        assertThat(persons.findActive(account.idPerson()).orElseThrow().name()).isEqualTo("Ada");
        assertThat(audits.logs()).singleElement()
                .satisfies(log -> assertThat(log.ipAddress()).contains("10.0.0.7"));
        assertThat(events.eventsOf(AccountRegistered.class))
                .containsExactly(new AccountRegistered("use0000009", EMAIL, NOW));
        assertThat(pending.registrations()).isEmpty();
    }

    @Test
    @DisplayName("a wrong code creates nothing and keeps the registration")
    void aWrongCodeCreatesNothing() {
        registered(NOW);
        String wrong = sentCode().equals("000000") ? "000001" : "000000";

        assertThatThrownBy(() -> serviceAt(NOW).verify(EMAIL, wrong))
                .isInstanceOf(InvalidVerificationCodeException.class);

        assertThat(users.users()).isEmpty();
        assertThat(pending.registrations()).hasSize(1);
        assertThat(events.events()).isEmpty();
    }

    @Test
    @DisplayName("an expired registration can no longer become an account nor get a code")
    void anExpiredRegistrationIsGone() {
        registered(NOW.minus(PendingRegistration.LIFETIME));
        String code = sentCode();

        assertThat(delivery.sent).isEmpty();
        assertThatThrownBy(() -> serviceAt(NOW).verify(EMAIL, code == null ? "123456" : code))
                .isInstanceOf(InvalidVerificationCodeException.class);
        assertThat(users.users()).isEmpty();
    }

    private record Sent(String userId, String recipient, String clearCode, Instant validUntil) {
    }

    private static final class RecordingDelivery implements EmailVerificationDeliveryPort {

        private final List<Sent> sent = new ArrayList<>();

        @Override
        public void deliver(String userId, String recipient, String clearCode,
                            Instant validUntil) {
            sent.add(new Sent(userId, recipient, clearCode, validUntil));
        }
    }
}
