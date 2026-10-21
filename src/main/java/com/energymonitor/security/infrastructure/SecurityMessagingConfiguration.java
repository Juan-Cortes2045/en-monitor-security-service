package com.energymonitor.security.infrastructure;

import com.energymonitor.security.adapter.out.messaging.OutboxPublisher;
import com.energymonitor.security.adapter.out.messaging.OutboxRelay;
import com.energymonitor.security.adapter.out.messaging.RabbitOutboxPublisher;
import com.energymonitor.security.adapter.out.persistence.repository.SecurityOutboxRepository;
import java.time.Clock;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

/**
 * The broker side of the outbox: the exchange this service publishes to, and the relay.
 *
 * <p>Only the exchange is declared here. The queues belong to the consumers, which declare and
 * bind their own; until one exists for a message type, {@link RabbitOutboxPublisher} gets the
 * message back and the relay keeps it pending.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SecurityMessagingProperties.class)
public class SecurityMessagingConfiguration {

    @Bean
    public TopicExchange securityExchange(SecurityMessagingProperties properties) {
        return new TopicExchange(properties.exchange(), true, false);
    }

    @Bean
    public OutboxPublisher outboxPublisher(RabbitTemplate rabbit,
                                           SecurityMessagingProperties properties, Clock clock) {
        return new RabbitOutboxPublisher(rabbit, properties.exchange(),
                properties.confirmTimeout(), clock);
    }

    @Bean
    public OutboxRelay outboxRelay(SecurityOutboxRepository outbox, OutboxPublisher publisher,
                                   SecurityMessagingProperties properties, Clock clock) {
        return new OutboxRelay(outbox, publisher, clock, properties.batchSize());
    }

    /** Runs the relay on a fixed delay, so a slow run never overlaps the next one. */
    @Configuration(proxyBeanMethods = false)
    @EnableScheduling
    @ConditionalOnProperty(name = "messaging.relay-enabled", havingValue = "true", matchIfMissing = true)
    static class RelaySchedule implements SchedulingConfigurer {

        private final OutboxRelay relay;
        private final SecurityMessagingProperties properties;

        RelaySchedule(OutboxRelay relay, SecurityMessagingProperties properties) {
            this.relay = relay;
            this.properties = properties;
        }

        @Override
        public void configureTasks(ScheduledTaskRegistrar registrar) {
            registrar.addFixedDelayTask(relay::relay, properties.pollInterval());
        }
    }
}
