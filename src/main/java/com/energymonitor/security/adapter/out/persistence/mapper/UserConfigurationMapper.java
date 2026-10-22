package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.UserConfigurationEntity;
import com.energymonitor.security.domain.model.UserConfiguration;
import org.springframework.stereotype.Component;

/**
 * Converts {@link UserConfiguration} to and from {@link UserConfigurationEntity}.
 *
 * <p>The optional preference fields become {@code null} columns and come back as empty
 * {@code Optional}s, so both empty states share one representation across the boundary.
 */
@Component
public class UserConfigurationMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param configuration the domain object
     * @return a detached entity ready to be persisted
     */
    public UserConfigurationEntity toEntity(UserConfiguration configuration) {
        UserConfigurationEntity entity = new UserConfigurationEntity();
        applyTo(entity, configuration);
        return entity;
    }

    /**
     * Copies the domain state onto an already managed entity, for updates.
     *
     * @param entity        the managed entity
     * @param configuration the domain object holding the new state
     */
    public void applyTo(UserConfigurationEntity entity, UserConfiguration configuration) {
        entity.setIdConfiguration(configuration.idConfiguration());
        entity.setUserId(configuration.idUser());
        entity.setNotifyByEmail(configuration.notifyByEmail());
        entity.setNotifyByPush(configuration.notifyByPush());
        entity.setColorTheme(configuration.colorTheme().orElse(null));
        entity.setLanguage(configuration.language().orElse(null));
        entity.setSocialProvider(configuration.socialProvider().orElse(null));
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public UserConfiguration toDomain(UserConfigurationEntity entity) {
        return new UserConfiguration(entity.getIdConfiguration(), entity.getUserId(),
                entity.isNotifyByEmail(), entity.isNotifyByPush(),
                entity.getColorTheme(), entity.getLanguage(), entity.getSocialProvider());
    }
}