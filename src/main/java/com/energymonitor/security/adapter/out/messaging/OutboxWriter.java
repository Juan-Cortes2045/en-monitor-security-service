package com.energymonitor.security.adapter.out.messaging;

import com.energymonitor.security.adapter.out.persistence.entity.SecurityOutboxEntity;
import com.energymonitor.security.adapter.out.persistence.repository.SecurityOutboxRepository;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.infrastructure.SecurityMessagingProperties;
import java.time.Clock;
import java.time.Instant;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Writes a message to the outbox.
 *
 * <p>Called from inside the use case's transaction, so the row is committed or rolled back
 * together with the change it announces. Publishing to the broker is left to
 * {@link OutboxRelay}.
 */
@Component
public class OutboxWriter {

    private final SecurityOutboxRepository outbox;
    private final IdentifierGeneratorPort identifiers;
    private final ObjectMapper json;
    private final Clock clock;
    private final boolean discardWritten;

    public OutboxWriter(SecurityOutboxRepository outbox, IdentifierGeneratorPort identifiers,
                        ObjectMapper json, Clock clock, SecurityMessagingProperties properties) {
        this.outbox = outbox;
        this.identifiers = identifiers;
        this.json = json;
        this.clock = clock;
        this.discardWritten = properties.discardWritten();
    }

    /**
     * @param type       the routing key, one of {@link SecurityMessageTypes}
     * @param payload    the body, serialized as JSON
     * @param occurredAt when the change happened
     * @param expiresAt  when the message stops being useful, or null if it never does
     */
    public void write(String type, Object payload, Instant occurredAt, Instant expiresAt) {
        SecurityOutboxEntity message = new SecurityOutboxEntity();
        message.setIdMessage(identifiers.generate());
        message.setMessageType(type);
        message.setPayload(json.writeValueAsString(payload));
        message.setOccurredAt(occurredAt);
        message.setExpiresAt(expiresAt);
        if (discardWritten) {
            message.setDiscardedAt(clock.instant());
            if (SecurityMessageTypes.CARRY_SECRETS.contains(type)) {
                message.setPayload(null);
            }
        }
        outbox.save(message);
    }
}
