package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.SystemRolePermissionEntity;
import com.energymonitor.security.adapter.out.persistence.entity.SystemRolePermissionId;
import com.energymonitor.security.adapter.out.persistence.support.Instants;
import com.energymonitor.security.domain.model.SystemRolePermission;
import org.springframework.stereotype.Component;

/**
 * Converts {@link SystemRolePermission} to and from {@link SystemRolePermissionEntity}.
 *
 * <p>Mirror of {@link UserSystemRoleMapper}: a pure two-way translation of a domain value
 * onto its composite-keyed row.
 */
@Component
public class SystemRolePermissionMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param grant the domain object
     * @return a detached entity ready to be persisted
     */
    public SystemRolePermissionEntity toEntity(SystemRolePermission grant) {
        return new SystemRolePermissionEntity(
                new SystemRolePermissionId(grant.idSystemRole(), grant.idPermission()),
                Instants.truncate(grant.assignedAt()));
    }

    /**
     * Updates an already existing row, used when reactivating a soft-deleted grant.
     *
     * @param entity the managed row
     * @param grant  the domain object holding the new state
     */
    public void applyTo(SystemRolePermissionEntity entity, SystemRolePermission grant) {
        entity.setAssignedAt(Instants.truncate(grant.assignedAt()));
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public SystemRolePermission toDomain(SystemRolePermissionEntity entity) {
        return new SystemRolePermission(entity.getSystemRoleId(), entity.getPermissionId(),
                entity.getAssignedAt());
    }
}