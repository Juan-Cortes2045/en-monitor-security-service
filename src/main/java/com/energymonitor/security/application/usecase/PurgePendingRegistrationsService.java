package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.port.in.PurgePendingRegistrations;
import com.energymonitor.security.application.port.out.PendingRegistrationPersistencePort;
import java.time.Clock;

/**
 * Forgets the registrations nobody verified. Their address had no mailbox behind it, or its owner
 * gave up: either way nothing of them should outlive {@code PendingRegistration.LIFETIME}.
 */
public class PurgePendingRegistrationsService implements PurgePendingRegistrations {

    private final PendingRegistrationPersistencePort registrations;
    private final Clock clock;

    public PurgePendingRegistrationsService(PendingRegistrationPersistencePort registrations,
                                            Clock clock) {
        this.registrations = registrations;
        this.clock = clock;
    }

    @Override
    public int purgeExpired() {
        return registrations.deleteExpired(clock.instant());
    }
}
