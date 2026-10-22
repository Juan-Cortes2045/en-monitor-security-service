package com.energymonitor.security.adapter.out.messaging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import com.energymonitor.security.adapter.out.persistence.entity.SecurityOutboxEntity;
import com.energymonitor.security.adapter.out.persistence.repository.SecurityOutboxRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Pageable;

@DisplayName("Outbox relay")
class OutboxRelayTest {

    private static final Instant NOW = Instant.parse("2026-10-20T15:00:00Z");

    private final SecurityOutboxRepository outbox = mock(SecurityOutboxRepository.class);
    private final RecordingPublisher publisher = new RecordingPublisher();
    private final OutboxRelay relay =
            new OutboxRelay(outbox, publisher, Clock.fixed(NOW, ZoneOffset.UTC), 50);

    @Test
    @DisplayName("publishes the pending messages oldest first and marks them as published")
    void publishesInOrder() {
        var first = message("msg0000001", SecurityMessageTypes.ACCOUNT_REGISTERED, null);
        var second = message("msg0000002", SecurityMessageTypes.ACCOUNT_DELETED, null);
        given(outbox.findPending(any(Pageable.class))).willReturn(List.of(first, second));

        int published = relay.relay();

        assertThat(published).isEqualTo(2);
        assertThat(publisher.ids).containsExactly("msg0000001", "msg0000002");
        assertThat(first.getPublishedAt()).isEqualTo(NOW);
        assertThat(second.getPublishedAt()).isEqualTo(NOW);
        assertThat(first.getPayload()).as("an account event keeps its payload").isNotNull();
    }

    @Test
    @DisplayName("erases the code of a mail request once the broker confirmed it")
    void erasesMailSecretAfterPublishing() {
        var mail = message("msg0000003", SecurityMessageTypes.MAIL_PASSWORD_RESET,
                NOW.plusSeconds(600));
        given(outbox.findPending(any(Pageable.class))).willReturn(List.of(mail));

        relay.relay();

        assertThat(publisher.ids).containsExactly("msg0000003");
        assertThat(mail.getPublishedAt()).isEqualTo(NOW);
        assertThat(mail.getPayload()).isNull();
    }

    @Test
    @DisplayName("discards an expired mail request unsent and erases its code")
    void discardsExpiredMail() {
        var expired = message("msg0000004", SecurityMessageTypes.MAIL_EMAIL_VERIFICATION, NOW);
        var next = message("msg0000005", SecurityMessageTypes.ACCOUNT_REGISTERED, null);
        given(outbox.findPending(any(Pageable.class))).willReturn(List.of(expired, next));

        int published = relay.relay();

        assertThat(published).isEqualTo(1);
        assertThat(publisher.ids).containsExactly("msg0000005");
        assertThat(expired.getDiscardedAt()).isEqualTo(NOW);
        assertThat(expired.getPublishedAt()).isNull();
        assertThat(expired.getPayload()).isNull();
    }

    @Test
    @DisplayName("stops at the first failure, so a later message never overtakes it")
    void stopsAtFirstFailure() {
        var failing = message("msg0000006", SecurityMessageTypes.ACCOUNT_DELETED, null);
        var later = message("msg0000007", SecurityMessageTypes.ACCOUNT_REGISTERED, null);
        given(outbox.findPending(any(Pageable.class))).willReturn(List.of(failing, later));
        publisher.failOn = "msg0000006";

        int published = relay.relay();

        assertThat(published).isZero();
        assertThat(publisher.ids).containsExactly("msg0000006");
        assertThat(failing.getPublishedAt()).isNull();
        assertThat(failing.getAttempts()).isEqualTo(1);
        assertThat(failing.getLastError()).isEqualTo("broker unavailable");
        assertThat(later.getPublishedAt()).isNull();
        assertThat(later.getAttempts()).isZero();
    }

    private static SecurityOutboxEntity message(String id, String type, Instant expiresAt) {
        var message = new SecurityOutboxEntity();
        message.setIdMessage(id);
        message.setMessageType(type);
        message.setPayload("{\"userId\":\"usr0000001\"}");
        message.setOccurredAt(NOW.minusSeconds(5));
        message.setExpiresAt(expiresAt);
        return message;
    }

    private static final class RecordingPublisher implements OutboxPublisher {

        private final List<String> ids = new ArrayList<>();
        private String failOn;

        @Override
        public void publish(String idMessage, String type, String payload, Instant occurredAt,
                            Instant expiresAt) {
            ids.add(idMessage);
            if (idMessage.equals(failOn)) {
                throw new IllegalStateException("broker unavailable");
            }
        }
    }
}
