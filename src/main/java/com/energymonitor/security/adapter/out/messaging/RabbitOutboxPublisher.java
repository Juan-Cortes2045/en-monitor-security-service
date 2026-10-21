package com.energymonitor.security.adapter.out.messaging;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageDeliveryMode;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

/**
 * Publishes outbox messages to RabbitMQ with publisher confirms.
 *
 * <p>A message counts as published only when the broker confirms it and it was routed to at
 * least one queue. The template is mandatory, so a message no queue is bound for comes back
 * instead of vanishing, and is retried until the consumer has declared its queue.
 *
 * <p>Messages are persistent, so a broker restart does not lose them, and a message with an
 * expiry carries it as the AMQP expiration, so the broker drops a code nobody can use anymore.
 */
public class RabbitOutboxPublisher implements OutboxPublisher {

    private final RabbitTemplate rabbit;
    private final String exchange;
    private final Duration confirmTimeout;
    private final Clock clock;
    private final Set<String> returned = ConcurrentHashMap.newKeySet();

    public RabbitOutboxPublisher(RabbitTemplate rabbit, String exchange, Duration confirmTimeout,
                                 Clock clock) {
        this.rabbit = rabbit;
        this.exchange = exchange;
        this.confirmTimeout = confirmTimeout;
        this.clock = clock;
        rabbit.setMandatory(true);
        rabbit.setReturnsCallback(back ->
                returned.add(back.getMessage().getMessageProperties().getMessageId()));
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

        returned.remove(idMessage);
        rabbit.invoke(operations -> {
            operations.send(exchange, type, message);
            operations.waitForConfirmsOrDie(confirmTimeout.toMillis());
            return null;
        });
        if (returned.remove(idMessage)) {
            throw new IllegalStateException("no queue is bound for " + type + " yet");
        }
    }
}
