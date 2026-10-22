package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.SystemRolePermission;
import java.util.List;
import java.util.Optional;

/**
 * Output port for persisting {@link SystemRolePermission} grants.
 */
public interface SystemRolePermissionPersistencePort {

    /**
     * Saves a grant: inserts a new row, or brings back a soft-deleted row with the same pair
     * of identifiers.
     *
     * @param grant the domain object
     * @return the same domain object
     */
    SystemRolePermission save(SystemRolePermission grant);

    /**
     * Soft-deletes the grant between a role and a permission.
     *
     * @param idSystemRole the role
     * @param idPermission the permission
     */
    void remove(String idSystemRole, String idPermission);

    /**
     * Finds the active grant by its composite key.
     *
     * @param idSystemRole the role
     * @param idPermission the permission
     * @return the grant, empty when soft-deleted or missing
     */
    Optional<SystemRolePermission> findActive(String idSystemRole, String idPermission);

    /**
     * Lists the active permissions granted to a role.
     *
     * @param idSystemRole the role
     * @return the grants
     */
    List<SystemRolePermission> listActiveBySystemRole(String idSystemRole);

    /**
     * Lists the active roles holding a permission.
     *
     * @param idPermission the permission
     * @return the grants
     */
    List<SystemRolePermission> listActiveByPermission(String idPermission);
}