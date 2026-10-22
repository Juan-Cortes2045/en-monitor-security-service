package com.energymonitor.security.adapter.out.messaging;

import com.energymonitor.security.adapter.out.persistence.entity.SecurityOutboxEntity;
import com.energymonitor.security.adapter.out.persistence.repository.SecurityOutboxRepository;
import java.time.Clock;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;

/**
 * Moves the outbox to the broker.
 *
 * <p>Each run takes the pending messages oldest first and publishes them one by one, waiting for
 * the broker's confirmation before marking a message as published. The first failure stops the
 * run, so a later message never overtakes an earlier one; the failed message is retried on the
 * next run, which is what makes delivery at-least-once. Consumers drop duplicates by message id.
 *
 * <p>A mail request whose code has already expired is discarded unsent, and once a mail request
 * is published or discarded its payload, which holds the code, is erased.
 *
 * <p>Runs on a single instance of the service. A second instance would publish the same rows
 * twice, which consumers tolerate, but it would also break the ordering above.
 */
public class OutboxRelay {

    private static final Logger LOG = LoggerFactory.getLogger(OutboxRelay.class);

    private static final int MAX_ERROR_LENGTH = 255;

    private final SecurityOutboxRepository outbox;
    private final OutboxPublisher publisher;
    private final Clock clock;
    private final int batchSize;

    public OutboxRelay(SecurityOutboxRepository outbox, OutboxPublisher publisher, Clock clock,
                       int batchSize) {
        this.outbox = outbox;
        this.publisher = publisher;
        this.clock = clock;
        this.batchSize = batchSize;
    }

    /**
     * Publishes what is pending.
     *
     * @return how many messages were published in this run
     */
    public int relay() {
        int published = 0;
        for (SecurityOutboxEntity message : outbox.findPending(PageRequest.of(0, batchSize))) {
            Instant now = clock.instant();
            if (message.getExpiresAt() != null && !message.getExpiresAt().isAfter(now)) {
                message.setDiscardedAt(now);
                eraseSecret(message);
                outbox.save(message);
                LOG.info("Outbox message {} ({}) expired before it could be published",
                        message.getIdMessage(), message.getMessageType());
                continue;
            }
            try {
                publisher.publish(message.getIdMessage(), message.getMessageType(),
                        message.getPayload(), message.getOccurredAt(), message.getExpiresAt());
            } catch (RuntimeException failure) {
                message.setAttempts(message.getAttempts() + 1);
                message.setLastError(truncate(failure.getMessage()));
                outbox.save(message);
                LOG.warn("Outbox message {} ({}) not published, attempt {}: {}",
                        message.getIdMessage(), message.getMessageType(), message.getAttempts(),
                        failure.getMessage());
                break;
            }
            message.setPublishedAt(clock.instant());
            eraseSecret(message);
            outbox.save(message);
            published++;
        }
        return published;
    }

    private static void eraseSecret(SecurityOutboxEntity message) {
        if (SecurityMessageTypes.CARRY_SECRETS.contains(message.getMessageType())) {
            message.setPayload(null);
        }
    }

    private static String truncate(String error) {
        if (error == null) {
            return null;
        }
        return error.length() <= MAX_ERROR_LENGTH ? error : error.substring(0, MAX_ERROR_LENGTH);
    }
}
