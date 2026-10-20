package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.SystemRole;
import java.util.List;
import java.util.Optional;

/**
 * Output port for persisting {@link SystemRole}.
 */
public interface SystemRolePersistencePort {

    /**
     * Inserts or updates the role.
     *
     * @param role the domain object
     * @return the same domain object
     */
    SystemRole save(SystemRole role);

    /**
     * Finds the active role by identifier.
     *
     * @param idSystemRole the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    Optional<SystemRole> findActive(String idSystemRole);

    /**
     * Finds the active role by name.
     *
     * @param name the role name
     * @return the domain object, empty when soft-deleted or missing
     */
    Optional<SystemRole> findActiveByName(String name);

    /**
     * Lists the active roles.
     *
     * @return the active roles
     */
    List<SystemRole> findAllActive();
}