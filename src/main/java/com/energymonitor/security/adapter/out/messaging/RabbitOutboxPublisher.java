package com.energymonitor.security.adapter.out.messaging;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageDeliveryMode;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

/**
 * Publishes outbox messages to RabbitMQ with correlated publisher confirms.
 *
 * <p>A message counts as published only when the broker confirms it and it was routed to at
 * least one queue. The template is mandatory, so a message no queue is bound for comes back
 * instead of vanishing, and is retried until the consumer has declared its queue.
 *
 * <p>The confirmation is correlated rather than simple on purpose: the broker sends the return
 * before the ack, but a simple confirm is waited for on the publishing thread while the return is
 * handled on another, so it may arrive after the wait ended and an unrouted message would pass as
 * published. With correlation data, Spring AMQP sets the returned message on it before it
 * completes the confirmation.
 *
 * <p>Messages are persistent, so a broker restart does not lose them, and a message with an
 * expiry carries it as the AMQP expiration, so the broker drops a code nobody can use anymore.
 */
public class RabbitOutboxPublisher implements OutboxPublisher {

    private final RabbitTemplate rabbit;
    private final String exchange;
    private final Duration confirmTimeout;
    private final Clock clock;

    public RabbitOutboxPublisher(RabbitTemplate rabbit, String exchange, Duration confirmTimeout,
                                 Clock clock) {
        this.rabbit = rabbit;
        this.exchange = exchange;
        this.confirmTimeout = confirmTimeout;
        this.clock = clock;
        rabbit.setMandatory(true);
    }

    @Override
    public void publish(String idMessage, String type, String payload, Instant occurredAt,
                        Instant expiresAt) {
        MessageProperties properties = new MessageProperties();
        properties.setMessageId(idMessage);
        properties.setType(type);
        properties.setContentType(MessageProperties.CONTENT_TYPE_JSON);
        properties.setContentEncoding(StandardCharsets.UTF_8.name());
        properties.setTimestamp(Date.from(occurredAt));
        properties.setDeliveryMode(MessageDeliveryMode.PERSISTENT);
        if (expiresAt != null) {
            long remaining = Math.max(1L, Duration.between(clock.instant(), expiresAt).toMillis());
            properties.setExpiration(Long.toString(remaining));
        }
        Message message = new Message(payload.getBytes(StandardCharsets.UTF_8), properties);

        CorrelationData correlation = new CorrelationData(idMessage);
        rabbit.send(exchange, type, message, correlation);
        CorrelationData.Confirm confirm = awaitConfirm(correlation, type);
        if (!confirm.ack()) {
            throw new IllegalStateException("the broker refused " + type + ": " + confirm.reason());
        }
        if (correlation.getReturned() != null) {
            throw new IllegalStateException("no queue is bound for " + type + " yet");
        }
    }

    private CorrelationData.Confirm awaitConfirm(CorrelationData correlation, String type) {
        try {
            return correlation.getFuture().get(confirmTimeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException late) {
            throw new IllegalStateException("the broker did not confirm " + type + " in time", late);
        } catch (ExecutionException failed) {
            throw new IllegalStateException("the confirmation of " + type + " failed", failed.getCause());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while waiting to confirm " + type, interrupted);
        }
    }
}
