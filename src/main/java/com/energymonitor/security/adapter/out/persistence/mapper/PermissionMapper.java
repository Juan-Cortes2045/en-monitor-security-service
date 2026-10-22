package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.PermissionEntity;
import com.energymonitor.security.domain.model.Permission;
import org.springframework.stereotype.Component;

/**
 * Converts {@link Permission} to and from {@link PermissionEntity}.
 */
@Component
public class PermissionMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param permission the domain object
     * @return a detached entity ready to be persisted
     */
    public PermissionEntity toEntity(Permission permission) {
        PermissionEntity entity = new PermissionEntity();
        applyTo(entity, permission);
        return entity;
    }

    /**
     * Copies the domain state onto an already managed entity, for updates.
     *
     * @param entity     the managed entity
     * @param permission the domain object holding the new state
     */
    public void applyTo(PermissionEntity entity, Permission permission) {
        entity.setIdPermission(permission.idPermission());
        entity.setCode(permission.code());
        entity.setName(permission.name());
        entity.setDescription(permission.description().orElse(null));
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public Permission toDomain(PermissionEntity entity) {
        return new Permission(entity.getIdPermission(), entity.getCode(), entity.getName(),
                entity.getDescription());
    }
}