package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.UserSystemRole;
import java.util.List;
import java.util.Optional;

/**
 * Output port for persisting {@link UserSystemRole} assignments.
 */
public interface UserSystemRolePersistencePort {

    /**
     * Saves an assignment: inserts a new row, or brings back a soft-deleted row with the same
     * pair of identifiers.
     *
     * @param assignment the domain object
     * @return the same domain object
     */
    UserSystemRole save(UserSystemRole assignment);

    /**
     * Soft-deletes the assignment between a user and a role.
     *
     * @param idUser       the user
     * @param idSystemRole the role
     */
    void remove(String idUser, String idSystemRole);

    /**
     * Finds the active assignment by its composite key.
     *
     * @param idUser       the user
     * @param idSystemRole the role
     * @return the assignment, empty when soft-deleted or missing
     */
    Optional<UserSystemRole> findActive(String idUser, String idSystemRole);

    /**
     * Lists the active roles assigned to a user.
     *
     * @param idUser the user
     * @return the assignments
     */
    List<UserSystemRole> listActiveByUser(String idUser);

    /**
     * Lists the active members of a role.
     *
     * @param idSystemRole the role
     * @return the assignments
     */
    List<UserSystemRole> listActiveBySystemRole(String idSystemRole);
}