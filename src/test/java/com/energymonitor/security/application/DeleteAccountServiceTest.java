package com.energymonitor.security.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.energymonitor.security.api.AccountDeleted;
import com.energymonitor.security.application.command.DeleteAccountCommand;
import com.energymonitor.security.application.exception.CurrentPasswordMismatchException;
import com.energymonitor.security.application.usecase.DeleteAccountService;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.UserSession;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
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

    private final DeleteAccountService service = new DeleteAccountService(users, persons, sessions,
            new UseCaseFixtures.FakePasswordHasherPort(), audits, events,
            new UseCaseFixtures.FakeIdentifierGeneratorPort(), Clock.fixed(NOW, ZoneOffset.UTC));

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
}
