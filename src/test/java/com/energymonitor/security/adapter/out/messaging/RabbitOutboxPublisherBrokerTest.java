package com.energymonitor.security.adapter.out.messaging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.core.AnonymousQueue;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

/**
 * The publisher against a real RabbitMQ: confirmed and routed, or refused.
 *
 * <p>Needs a broker on {@code RABBITMQ_HOST:RABBITMQ_PORT} (localhost:5672 by default) with the
 * credentials of {@code RABBITMQ_USERNAME} and {@code RABBITMQ_PASSWORD}; without one it is
 * skipped rather than failed, so the suite still runs where no broker exists.
 */
@DisplayName("RabbitMQ outbox publisher")
class RabbitOutboxPublisherBrokerTest {

    private static final String HOST = env("RABBITMQ_HOST", "localhost");
    private static final int PORT = Integer.parseInt(env("RABBITMQ_PORT", "5672"));

    private CachingConnectionFactory connections;
    private RabbitAdmin admin;
    private RabbitTemplate rabbit;
    private TopicExchange exchange;
    private RabbitOutboxPublisher publisher;

    @BeforeEach
    void connect() {
        assumeTrue(reachable(), "no RabbitMQ on " + HOST + ":" + PORT);
        connections = new CachingConnectionFactory(HOST, PORT);
        connections.setUsername(env("RABBITMQ_USERNAME", "guest"));
        connections.setPassword(env("RABBITMQ_PASSWORD", "guest"));
        connections.setPublisherConfirmType(CachingConnectionFactory.ConfirmType.SIMPLE);
        connections.setPublisherReturns(true);
        admin = new RabbitAdmin(connections);
        exchange = new TopicExchange("test.security." + UUID.randomUUID(), false, true);
        admin.declareExchange(exchange);
        rabbit = new RabbitTemplate(connections);
        publisher = new RabbitOutboxPublisher(rabbit, exchange.getName(), Duration.ofSeconds(5),
                Clock.systemUTC());
    }

    @AfterEach
    void disconnect() {
        if (admin != null) {
            admin.deleteExchange(exchange.getName());
            connections.destroy();
        }
    }

    @Test
    @DisplayName("delivers a routed message with its id, type and expiration")
    void deliversRoutedMessage() {
        Queue queue = new AnonymousQueue();
        admin.declareQueue(queue);
        admin.declareBinding(BindingBuilder.bind(queue).to(exchange)
                .with(SecurityMessageTypes.MAIL_EMAIL_VERIFICATION));

        publisher.publish("msg0000001", SecurityMessageTypes.MAIL_EMAIL_VERIFICATION,
                "{\"code\":\"123456\"}", Instant.now(), Instant.now().plusSeconds(600));

        Message received = rabbit.receive(queue.getName(), 5_000);
        assertThat(received).isNotNull();
        assertThat(new String(received.getBody(), StandardCharsets.UTF_8))
                .isEqualTo("{\"code\":\"123456\"}");
        assertThat(received.getMessageProperties().getMessageId()).isEqualTo("msg0000001");
        assertThat(received.getMessageProperties().getType())
                .isEqualTo(SecurityMessageTypes.MAIL_EMAIL_VERIFICATION);
        assertThat(received.getMessageProperties().getExpiration()).isNotNull();
    }

    @Test
    @DisplayName("refuses a message no queue is bound for, so the relay keeps it pending")
    void refusesUnroutedMessage() {
        assertThatThrownBy(() -> publisher.publish("msg0000002",
                SecurityMessageTypes.ACCOUNT_DELETED, "{}", Instant.now(), null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(SecurityMessageTypes.ACCOUNT_DELETED);
    }

    private static boolean reachable() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(HOST, PORT), 500);
            return true;
        } catch (IOException unreachable) {
            return false;
        }
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }
}
