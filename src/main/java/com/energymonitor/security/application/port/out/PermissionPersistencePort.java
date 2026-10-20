package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.Permission;
import java.util.List;
import java.util.Optional;

/**
 * Output port for persisting {@link Permission}.
 */
public interface PermissionPersistencePort {

    /**
     * Inserts or updates the permission.
     *
     * @param permission the domain object
     * @return the same domain object
     */
    Permission save(Permission permission);

    /**
     * Finds the active permission by identifier.
     *
     * @param idPermission the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    Optional<Permission> findActive(String idPermission);

    /**
     * Finds the active permission by code.
     *
     * @param code the stable permission code
     * @return the domain object, empty when soft-deleted or missing
     */
    Optional<Permission> findActiveByCode(String code);

    /**
     * Lists the active permissions.
     *
     * @return the active permissions
     */
    List<Permission> findAllActive();
}