package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.SecurityConfigurationEntity;
import com.energymonitor.security.domain.model.SecurityConfiguration;
import org.springframework.stereotype.Component;

/**
 * Converts {@link SecurityConfiguration} to and from {@link SecurityConfigurationEntity}.
 */
@Component
public class SecurityConfigurationMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param configuration the domain object
     * @return a detached entity ready to be persisted
     */
    public SecurityConfigurationEntity toEntity(SecurityConfiguration configuration) {
        SecurityConfigurationEntity entity = new SecurityConfigurationEntity();
        applyTo(entity, configuration);
        return entity;
    }

    /**
     * Copies the domain state onto an already managed entity, for updates.
     *
     * @param entity        the managed entity
     * @param configuration the domain object holding the new state
     */
    public void applyTo(SecurityConfigurationEntity entity, SecurityConfiguration configuration) {
        entity.setIdSecurityConfiguration(configuration.idSecurityConfiguration());
        entity.setConfigName(configuration.configName());
        entity.setConfigValue(configuration.configValue());
        entity.setDescription(configuration.description().orElse(null));
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public SecurityConfiguration toDomain(SecurityConfigurationEntity entity) {
        return new SecurityConfiguration(entity.getIdSecurityConfiguration(),
                entity.getConfigName(), entity.getConfigValue(), entity.getDescription());
    }
}