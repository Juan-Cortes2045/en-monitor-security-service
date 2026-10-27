package com.energymonitor.security.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.energymonitor.security.adapter.out.security.InMemoryResetAttemptLimiter;
import com.energymonitor.security.adapter.out.security.PepperedHmacResetCodeHasher;
import com.energymonitor.security.api.AccountDeleted;
import com.energymonitor.security.api.AccountDeletionBlockedException;
import com.energymonitor.security.application.command.DeleteAccountCommand;
import com.energymonitor.security.application.exception.AccountDeletionCheckUnavailableException;
import com.energymonitor.security.application.exception.CurrentPasswordMismatchException;
import com.energymonitor.security.application.exception.DeletionCodeNotApplicableException;
import com.energymonitor.security.application.exception.InvalidVerificationCodeException;
import com.energymonitor.security.application.usecase.DeleteAccountService;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.UserSession;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class DeleteAccountServiceTest {

    private static final Instant NOW = Instant.parse("2026-03-01T12:00:00Z");

    private final UseCaseFixtures.FakeUserPersistencePort users =
            new UseCaseFixtures.FakeUserPersistencePort();
    private final UseCaseFixtures.FakePersonPersistencePort persons =
            new UseCaseFixtures.FakePersonPersistencePort();
    private final UseCaseFixtures.FakeUserSessionPersistencePort sessions =
            new UseCaseFixtures.FakeUserSessionPersistencePort();
    private final UseCaseFixtures.FakeAuditLogPersistencePort audits =
            new UseCaseFixtures.FakeAuditLogPersistencePort();
    private final UseCaseFixtures.FakeAccountEventPublisherPort events =
            new UseCaseFixtures.FakeAccountEventPublisherPort();

    /** What the backend answers; null lets the deletion go ahead. */
    private RuntimeException refusal;

    private final List<String> mailedCodes = new ArrayList<>();

    private final DeleteAccountService service = new DeleteAccountService(users, persons, sessions,
            new UseCaseFixtures.FakePasswordHasherPort(), audits, events,
            idUser -> {
                if (refusal != null) {
                    throw refusal;
                }
            },
            new UseCaseFixtures.FakeIdentifierGeneratorPort(),
            new PepperedHmacResetCodeHasher("test-pepper-of-sufficient-length-0123"),
            (userId, recipient, code, validUntil) -> mailedCodes.add(code),
            new InMemoryResetAttemptLimiter(5, Duration.ofMinutes(15), Clock.fixed(NOW, ZoneOffset.UTC)),
            Clock.fixed(NOW, ZoneOffset.UTC));

    private void googleAccount() {
        users.findActive("use0000001").orElseThrow().bindGoogleAccount("g-sub-1");
    }

    @BeforeEach
    void seed() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        persons.seed("per0000001");
        sessions.save(UserSession.open("ses0000001", "use0000001", NOW.minusSeconds(60),
                NOW.plus(Duration.ofDays(7)), null, null));
    }

    @Test
    @DisplayName("deletes the account and its person, closes its sessions and announces it")
    void deletesTheAccount() {
        service.delete(new DeleteAccountCommand("use0000001", UseCaseFixtures.PASSWORD, "10.0.0.1"));

        assertThat(users.findActive("use0000001")).isEmpty();
        assertThat(persons.findActive("per0000001")).isEmpty();
        assertThat(sessions.findActive("ses0000001").orElseThrow().closedAt()).contains(NOW);
        assertThat(audits.logs()).singleElement()
                .satisfies(log -> assertThat(log.action()).isEqualTo(AuditAction.DELETE));
        assertThat(events.events()).containsExactly(new AccountDeleted("use0000001", NOW));
    }

    @Test
    @DisplayName("a wrong password deletes nothing and announces nothing")
    void wrongPasswordDeletesNothing() {
        assertThatThrownBy(() -> service.delete(
                new DeleteAccountCommand("use0000001", "not-the-password", "10.0.0.1")))
                .isInstanceOf(CurrentPasswordMismatchException.class);

        assertThat(users.findActive("use0000001")).isPresent();
        assertThat(persons.findActive("per0000001")).isPresent();
        assertThat(sessions.findActive("ses0000001").orElseThrow().closedAt()).isEmpty();
        assertThat(events.events()).isEmpty();
    }

    @Test
    @DisplayName("a refusal of the backend deletes nothing and announces nothing")
    void refusedDeletionDeletesNothing() {
        refusal = new AccountDeletionBlockedException("only owner");

        assertThatThrownBy(() -> service.delete(
                new DeleteAccountCommand("use0000001", UseCaseFixtures.PASSWORD, "10.0.0.1")))
                .isSameAs(refusal);

        assertNothingDeleted();
    }

    @Test
    @DisplayName("without an answer from the backend nothing is deleted")
    void uncheckedDeletionDeletesNothing() {
        refusal = new AccountDeletionCheckUnavailableException("timeout");

        assertThatThrownBy(() -> service.delete(
                new DeleteAccountCommand("use0000001", UseCaseFixtures.PASSWORD, "10.0.0.1")))
                .isSameAs(refusal);

        assertNothingDeleted();
    }

    private void assertNothingDeleted() {
        assertThat(users.findActive("use0000001")).isPresent();
        assertThat(persons.findActive("per0000001")).isPresent();
        assertThat(sessions.findActive("ses0000001").orElseThrow().closedAt()).isEmpty();
        assertThat(audits.logs()).isEmpty();
        assertThat(events.events()).isEmpty();
    }

    @Test
    @DisplayName("an account created with Google is deleted with the code mailed to it, without a password")
    void aGoogleAccountIsDeletedWithTheMailedCode() {
        googleAccount();

        service.sendDeletionCode("use0000001");
        assertThat(mailedCodes).singleElement().satisfies(code -> assertThat(code).matches("\\d{6}"));
        service.delete(new DeleteAccountCommand("use0000001", null, mailedCodes.getFirst(), "10.0.0.1"));

        assertThat(users.findActive("use0000001")).isEmpty();
        assertThat(events.events()).containsExactly(new AccountDeleted("use0000001", NOW));
    }

    @Test
    @DisplayName("a Google account is not deleted with a wrong code, nor with its password")
    void aGoogleAccountNeedsTheRightCode() {
        googleAccount();
        service.sendDeletionCode("use0000001");
        String wrong = mailedCodes.getFirst().equals("000000") ? "000001" : "000000";

        assertThatThrownBy(() -> service.delete(
                new DeleteAccountCommand("use0000001", null, wrong, "10.0.0.1")))
                .isInstanceOf(InvalidVerificationCodeException.class);
        assertThatThrownBy(() -> service.delete(
                new DeleteAccountCommand("use0000001", UseCaseFixtures.PASSWORD, "10.0.0.1")))
                .isInstanceOf(InvalidVerificationCodeException.class);

        assertThat(users.findActive("use0000001")).isPresent();
        assertThat(events.events()).isEmpty();
    }

    @Test
    @DisplayName("an account with a password gets no deletion code: it confirms with the password")
    void anAccountWithAPasswordGetsNoCode() {
        assertThatThrownBy(() -> service.sendDeletionCode("use0000001"))
                .isInstanceOf(DeletionCodeNotApplicableException.class);

        assertThat(mailedCodes).isEmpty();
    }
}
