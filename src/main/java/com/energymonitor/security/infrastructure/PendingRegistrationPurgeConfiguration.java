package com.energymonitor.security.infrastructure;

import com.energymonitor.security.application.port.in.PurgePendingRegistrations;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

/**
 * Removes every hour the registrations whose verification code never came back, so a request for
 * an address nobody reads lasts at most a day and an hour.
 *
 * <p>{@code security.registration.purge-enabled=false} turns it off.
 */
@Configuration(proxyBeanMethods = false)
@EnableScheduling
@ConditionalOnProperty(name = "security.registration.purge-enabled", havingValue = "true",
        matchIfMissing = true)
public class PendingRegistrationPurgeConfiguration implements SchedulingConfigurer {

    private static final Logger LOG = LoggerFactory.getLogger(PendingRegistrationPurgeConfiguration.class);
    private static final Duration INTERVAL = Duration.ofHours(1);

    private final PurgePendingRegistrations purge;

    PendingRegistrationPurgeConfiguration(PurgePendingRegistrations purge) {
        this.purge = purge;
    }

    @Override
    public void configureTasks(ScheduledTaskRegistrar registrar) {
        registrar.addFixedDelayTask(this::purgeExpired, INTERVAL);
    }

    private void purgeExpired() {
        try {
            int removed = purge.purgeExpired();
            if (removed > 0) {
                LOG.info("Removed {} registrations that were never verified", removed);
            }
        } catch (RuntimeException failure) {
            LOG.warn("The expired registrations could not be removed; retrying in an hour", failure);
        }
    }
}
