package com.energymonitor.security.adapter.out.messaging;

import com.energymonitor.security.adapter.out.messaging.SecurityMessagePayloads.AccountAdministeredPayload;
import com.energymonitor.security.adapter.out.messaging.SecurityMessagePayloads.AccountDeletedPayload;
import com.energymonitor.security.adapter.out.messaging.SecurityMessagePayloads.AccountFirstSignedInPayload;
import com.energymonitor.security.adapter.out.messaging.SecurityMessagePayloads.AccountRegisteredPayload;
import com.energymonitor.security.api.AccountAdministered;
import com.energymonitor.security.api.AccountDeleted;
import com.energymonitor.security.api.AccountFirstSignedIn;
import com.energymonitor.security.api.AccountRegistered;
import com.energymonitor.security.application.port.out.AccountEventPublisherPort;
import org.springframework.stereotype.Component;

/**
 * Announces account events to other services through the outbox.
 *
 * <p>The use cases raise these events inside their transaction, so the message is committed
 * with the change or not at all; {@link OutboxRelay} delivers it afterwards.
 */
@Component
public class OutboxAccountEventPublisher implements AccountEventPublisherPort {

    private final OutboxWriter outbox;

    public OutboxAccountEventPublisher(OutboxWriter outbox) {
        this.outbox = outbox;
    }

    @Override
    public void accountDeleted(AccountDeleted event) {
        outbox.write(SecurityMessageTypes.ACCOUNT_DELETED,
                new AccountDeletedPayload(event.userId(), event.deletedAt()),
                event.deletedAt(), null);
    }

    @Override
    public void accountRegistered(AccountRegistered event) {
        outbox.write(SecurityMessageTypes.ACCOUNT_REGISTERED,
                new AccountRegisteredPayload(event.userId(), event.email(), event.occurredAt()),
                event.occurredAt(), null);
    }

    @Override
    public void accountAdministered(AccountAdministered event) {
        outbox.write(SecurityMessageTypes.ACCOUNT_ADMINISTERED,
                new AccountAdministeredPayload(event.actorId(), event.userId(),
                        event.action().name(), event.detail(), event.occurredAt()),
                event.occurredAt(), null);
    }

    @Override
    public void accountFirstSignedIn(AccountFirstSignedIn event) {
        outbox.write(SecurityMessageTypes.ACCOUNT_FIRST_SIGNED_IN,
                new AccountFirstSignedInPayload(event.userId(), event.occurredAt()),
                event.occurredAt(), null);
    }
}
