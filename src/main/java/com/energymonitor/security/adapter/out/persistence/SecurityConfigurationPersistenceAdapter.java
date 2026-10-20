package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.SecurityConfigurationEntity;
import com.energymonitor.security.adapter.out.persistence.mapper.SecurityConfigurationMapper;
import com.energymonitor.security.adapter.out.persistence.repository.SecurityConfigurationRepository;
import com.energymonitor.security.application.port.out.SecurityConfigurationPersistencePort;
import com.energymonitor.security.domain.model.SecurityConfiguration;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for {@link SecurityConfiguration}.
 *
 * <p>Implements {@link SecurityConfigurationPersistencePort} so the application reaches these
 * rows through an output port like every other persisted concept. The adapter was previously
 * a bare component with no interface behind it, which left the persistence layer reachable
 * only to tests and gave the application no sanctioned way to read a setting.
 */
@Component
public class SecurityConfigurationPersistenceAdapter
        implements SecurityConfigurationPersistencePort {

    private final SecurityConfigurationRepository repository;
    private final SecurityConfigurationMapper mapper;

    public SecurityConfigurationPersistenceAdapter(SecurityConfigurationRepository repository,
            SecurityConfigurationMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Inserts or updates the configuration entry.
     *
     * @param configuration the domain object
     * @return the same domain object
     */
    @Override
    public SecurityConfiguration save(SecurityConfiguration configuration) {
        SecurityConfigurationEntity entity = repository
                .findById(configuration.idSecurityConfiguration())
                .map(existing -> {
                    mapper.applyTo(existing, configuration);
                    return existing;
                })
                .orElseGet(() -> mapper.toEntity(configuration));
        repository.save(entity);
        return configuration;
    }

    /**
     * Finds the active entry by identifier.
     *
     * @param idSecurityConfiguration the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    @Override
    public Optional<SecurityConfiguration> findActive(String idSecurityConfiguration) {
        return repository.findById(idSecurityConfiguration)
                .filter(entity -> entity.getDeletedAt() == null)
                .map(mapper::toDomain);
    }

    /**
     * Finds the active entry by configuration name.
     *
     * @param configName the configuration key
     * @return the domain object, empty when soft-deleted or missing
     */
    @Override
    public Optional<SecurityConfiguration> findActiveByName(String configName) {
        return repository.findByConfigNameAndDeletedAtIsNull(configName)
                .map(mapper::toDomain);
    }
}