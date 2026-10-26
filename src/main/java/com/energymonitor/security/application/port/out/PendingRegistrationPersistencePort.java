package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PendingRegistration;
import java.time.Instant;
import java.util.Optional;

/** Storage of the registrations waiting for their verification code. */
public interface PendingRegistrationPersistencePort {

    /** Stores the request, replacing any other one for the same address. */
    PendingRegistration save(PendingRegistration registration);

    /** @return the request for the address, expired or not */
    Optional<PendingRegistration> findByEmail(Email email);

    void delete(String idUser);

    /** @return how many requests expired at or before {@code instant} were removed */
    int deleteExpired(Instant instant);
}
