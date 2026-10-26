package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.PendingRegistrationEntity;
import com.energymonitor.security.adapter.out.persistence.repository.PendingRegistrationRepository;
import com.energymonitor.security.application.port.out.PendingRegistrationPersistencePort;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordHash;
import com.energymonitor.security.domain.model.PendingRegistration;
import java.time.Instant;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for {@link PendingRegistration}. Rows are deleted, never soft-deleted: a
 * request that became an account or expired has nothing left to keep.
 */
@Component
public class PendingRegistrationPersistenceAdapter implements PendingRegistrationPersistencePort {

    private final PendingRegistrationRepository repository;

    public PendingRegistrationPersistenceAdapter(PendingRegistrationRepository repository) {
        this.repository = repository;
    }

    @Override
    public PendingRegistration save(PendingRegistration registration) {
        // The address is unique in the table: an earlier request for it gives way to this one.
        repository.deleteByEmail(registration.email().value());
        repository.save(toEntity(registration));
        return registration;
    }

    @Override
    public Optional<PendingRegistration> findByEmail(Email email) {
        return repository.findByEmail(email.value()).map(PendingRegistrationPersistenceAdapter::toDomain);
    }

    @Override
    public void delete(String idUser) {
        repository.deleteById(idUser);
    }

    @Override
    public int deleteExpired(Instant instant) {
        return repository.deleteExpired(instant);
    }

    private static PendingRegistrationEntity toEntity(PendingRegistration registration) {
        PendingRegistrationEntity entity = new PendingRegistrationEntity();
        entity.setIdUser(registration.idUser());
        entity.setEmail(registration.email().value());
        entity.setName(registration.name());
        entity.setLastName(registration.lastName().orElse(null));
        entity.setPasswordHash(registration.passwordHash().value());
        entity.setProfileImage(registration.profileImage().orElse(null));
        entity.setIpAddress(registration.ipAddress().orElse(null));
        entity.setRequestedAt(registration.requestedAt());
        entity.setExpiresAt(registration.expiresAt());
        return entity;
    }

    private static PendingRegistration toDomain(PendingRegistrationEntity entity) {
        return new PendingRegistration(entity.getIdUser(), Email.of(entity.getEmail()),
                entity.getName(), entity.getLastName(), PasswordHash.of(entity.getPasswordHash()),
                entity.getProfileImage(), entity.getIpAddress(), entity.getRequestedAt(),
                entity.getExpiresAt());
    }
}
