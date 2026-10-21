package com.energymonitor.security.adapter.out.messaging;

import java.time.Instant;

/**
 * Hands one outbox message to the broker and returns only once the broker has taken
 * responsibility for it.
 */
public interface OutboxPublisher {

    /**
     * @param idMessage  the message id, which consumers use to drop duplicates
     * @param type       the routing key
     * @param payload    the JSON body
     * @param occurredAt when the change happened
     * @param expiresAt  when the message stops being useful, or null
     * @throws RuntimeException when the broker did not confirm the message, or no queue took it
     */
    void publish(String idMessage, String type, String payload, Instant occurredAt,
                 Instant expiresAt);
}
