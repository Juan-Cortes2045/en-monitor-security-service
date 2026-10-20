package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.UserConfigurationEntity;
import com.energymonitor.security.adapter.out.persistence.mapper.UserConfigurationMapper;
import com.energymonitor.security.adapter.out.persistence.repository.UserConfigurationRepository;
import com.energymonitor.security.application.port.out.UserConfigurationPersistencePort;
import com.energymonitor.security.domain.model.UserConfiguration;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for {@link UserConfiguration}.
 *
 * <p>Implements {@link UserConfigurationPersistencePort} so the application reaches these
 * preferences through an output port like every other persisted concept, rather than through
 * the adapter class itself.
 */
@Component
public class UserConfigurationPersistenceAdapter implements UserConfigurationPersistencePort {

    private final UserConfigurationRepository repository;
    private final UserConfigurationMapper mapper;

    public UserConfigurationPersistenceAdapter(UserConfigurationRepository repository,
            UserConfigurationMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Inserts or updates the configuration.
     *
     * @param configuration the domain object
     * @return the same domain object
     */
    @Override
    public UserConfiguration save(UserConfiguration configuration) {
        UserConfigurationEntity entity = repository.findById(configuration.idConfiguration())
                .map(existing -> {
                    if (existing.getDeletedAt() != null) {
                        existing.setDeletedAt(null);
                    }
                    mapper.applyTo(existing, configuration);
                    return existing;
                })
                .orElseGet(() -> mapper.toEntity(configuration));
        repository.save(entity);
        return configuration;
    }

    /**
     * Finds the active configuration by identifier.
     *
     * @param idConfiguration the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    @Override
    public Optional<UserConfiguration> findActive(String idConfiguration) {
        return repository.findById(idConfiguration)
                .filter(entity -> entity.getDeletedAt() == null)
                .map(mapper::toDomain);
    }

    /**
     * Finds the active configuration of a user.
     *
     * @param idUser the owner
     * @return the domain object, empty when soft-deleted or missing
     */
    @Override
    public Optional<UserConfiguration> findActiveByUser(String idUser) {
        return repository.findByUserIdAndDeletedAtIsNull(idUser)
                .map(mapper::toDomain);
    }
}