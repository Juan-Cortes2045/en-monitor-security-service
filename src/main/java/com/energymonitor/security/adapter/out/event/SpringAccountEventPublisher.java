package com.energymonitor.security.adapter.out.event;

import com.energymonitor.security.api.AccountAdministered;
import com.energymonitor.security.api.AccountDeleted;
import com.energymonitor.security.api.AccountRegistered;
import com.energymonitor.security.application.port.out.AccountEventPublisherPort;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

/**
 * Publishes account events as Spring application events, delivered synchronously so listeners
 * run inside the publishing transaction.
 */
@Component
public class SpringAccountEventPublisher implements AccountEventPublisherPort {

    private final ApplicationEventPublisher publisher;

    public SpringAccountEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public void accountDeleted(AccountDeleted event) {
        publisher.publishEvent(event);
    }

    @Override
    public void accountRegistered(AccountRegistered event) {
        publisher.publishEvent(event);
    }

    @Override
    public void accountAdministered(AccountAdministered event) {
        publisher.publishEvent(event);
    }
}
