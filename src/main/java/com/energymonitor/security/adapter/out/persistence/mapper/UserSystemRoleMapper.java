package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.UserSystemRoleEntity;
import com.energymonitor.security.adapter.out.persistence.entity.UserSystemRoleId;
import com.energymonitor.security.adapter.out.persistence.support.Instants;
import com.energymonitor.security.domain.model.UserSystemRole;
import org.springframework.stereotype.Component;

/**
 * Converts {@link UserSystemRole} to and from {@link UserSystemRoleEntity}.
 *
 * <p>The domain object is a value, so the mapping is a pure two-way translation. Both
 * identifiers form the composite key; {@code assignedAt} is truncated to the column
 * precision so the rehydrated aggregate and the stored row agree on the assignment time.
 */
@Component
public class UserSystemRoleMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param assignment the domain object
     * @return a detached entity ready to be persisted
     */
    public UserSystemRoleEntity toEntity(UserSystemRole assignment) {
        return new UserSystemRoleEntity(
                new UserSystemRoleId(assignment.idUser(), assignment.idSystemRole()),
                Instants.truncate(assignment.assignedAt()));
    }

    /**
     * Updates an already existing row, used when reactivating a soft-deleted assignment.
     *
     * <p>The composite key is the row identity and does not change; only the assignment
     * time is refreshed. Clearing {@code deleted_at} is the adapter's decision when the row
     * was soft-deleted, not the mapper's.
     *
     * @param entity     the managed row
     * @param assignment the domain object holding the new state
     */
    public void applyTo(UserSystemRoleEntity entity, UserSystemRole assignment) {
        entity.setAssignedAt(Instants.truncate(assignment.assignedAt()));
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public UserSystemRole toDomain(UserSystemRoleEntity entity) {
        return new UserSystemRole(entity.getUserId(), entity.getSystemRoleId(),
                entity.getAssignedAt());
    }
}