package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.SystemRoleEntity;
import com.energymonitor.security.domain.model.SystemRole;
import org.springframework.stereotype.Component;

/**
 * Converts {@link SystemRole} to and from {@link SystemRoleEntity}.
 */
@Component
public class SystemRoleMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param systemRole the domain object
     * @return a detached entity ready to be persisted
     */
    public SystemRoleEntity toEntity(SystemRole systemRole) {
        SystemRoleEntity entity = new SystemRoleEntity();
        applyTo(entity, systemRole);
        return entity;
    }

    /**
     * Copies the domain state onto an already managed entity, for updates.
     *
     * @param entity     the managed entity
     * @param systemRole the domain object holding the new state
     */
    public void applyTo(SystemRoleEntity entity, SystemRole systemRole) {
        entity.setIdSystemRole(systemRole.idSystemRole());
        entity.setName(systemRole.name());
        entity.setDescription(systemRole.description().orElse(null));
        entity.setEnabled(systemRole.isEnabled());
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public SystemRole toDomain(SystemRoleEntity entity) {
        return new SystemRole(entity.getIdSystemRole(), entity.getName(),
                entity.getDescription(), entity.isEnabled());
    }
}