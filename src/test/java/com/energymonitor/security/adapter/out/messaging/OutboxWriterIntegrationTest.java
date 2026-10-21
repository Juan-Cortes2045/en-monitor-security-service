package com.energymonitor.security.adapter.out.messaging;

import static org.assertj.core.api.Assertions.assertThat;

import com.energymonitor.security.adapter.out.persistence.entity.SecurityOutboxEntity;
import com.energymonitor.security.adapter.out.persistence.repository.SecurityOutboxRepository;
import com.energymonitor.security.api.AccountDeleted;
import com.energymonitor.security.api.EmailVerificationDeliveryPort;
import com.energymonitor.security.application.port.out.AccountEventPublisherPort;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The outbox row shares the fate of the transaction that writes it: committed with the change,
 * or gone with it. Runs against the shared MySQL schema and removes its own rows, so it turns off
 * the test profile's {@code discard-written} to see the rows as production writes them.
 */
@SpringBootTest(properties = "messaging.discard-written=false")
@DisplayName("Outbox writer")
class OutboxWriterIntegrationTest extends JwtKeyedTest {

    @Autowired
    private AccountEventPublisherPort events;

    @Autowired
    private EmailVerificationDeliveryPort verificationDelivery;

    @Autowired
    private SecurityOutboxRepository outbox;

    @Autowired
    private PlatformTransactionManager transactions;

    private final String userId = "t" + UUID.randomUUID().toString().replace("-", "").substring(0, 9);

    @AfterEach
    void removeRows() {
        outbox.deleteAll(rowsOfUser());
    }

    @Test
    @DisplayName("an event raised in a committed transaction stays in the outbox")
    void committedEventIsKept() {
        Instant deletedAt = Instant.parse("2026-10-20T15:00:00Z");

        new TransactionTemplate(transactions).executeWithoutResult(status ->
                events.accountDeleted(new AccountDeleted(userId, deletedAt)));

        List<SecurityOutboxEntity> rows = rowsOfUser();
        assertThat(rows).hasSize(1);
        SecurityOutboxEntity row = rows.getFirst();
        assertThat(row.getIdMessage()).hasSize(10);
        assertThat(row.getMessageType()).isEqualTo(SecurityMessageTypes.ACCOUNT_DELETED);
        assertThat(row.getPayload()).contains("\"userId\":\"" + userId + "\"")
                .contains("2026-10-20T15:00:00Z");
        assertThat(row.getOccurredAt()).isEqualTo(deletedAt);
        assertThat(row.getPublishedAt()).isNull();
    }

    @Test
    @DisplayName("an event raised in a rolled back transaction leaves nothing behind")
    void rolledBackEventIsGone() {
        new TransactionTemplate(transactions).executeWithoutResult(status -> {
            events.accountDeleted(new AccountDeleted(userId, Instant.now()));
            status.setRollbackOnly();
        });

        assertThat(rowsOfUser()).isEmpty();
    }

    @Test
    @DisplayName("a mail request expires with its code")
    void mailRequestExpiresWithTheCode() {
        Instant validUntil = Instant.parse("2026-10-20T15:15:00Z");

        verificationDelivery.deliver(userId, "someone@example.com", "123456", validUntil);

        List<SecurityOutboxEntity> rows = rowsOfUser();
        assertThat(rows).hasSize(1);
        assertThat(rows.getFirst().getMessageType())
                .isEqualTo(SecurityMessageTypes.MAIL_EMAIL_VERIFICATION);
        assertThat(rows.getFirst().getExpiresAt()).isEqualTo(validUntil);
    }

    private List<SecurityOutboxEntity> rowsOfUser() {
        return outbox.findAll().stream()
                .filter(row -> row.getPayload() != null && row.getPayload().contains(userId))
                .toList();
    }
}
