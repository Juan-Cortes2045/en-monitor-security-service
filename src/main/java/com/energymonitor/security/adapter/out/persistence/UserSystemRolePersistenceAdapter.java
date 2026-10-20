package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.UserSystemRoleEntity;
import com.energymonitor.security.adapter.out.persistence.entity.UserSystemRoleId;
import com.energymonitor.security.adapter.out.persistence.mapper.UserSystemRoleMapper;
import com.energymonitor.security.adapter.out.persistence.repository.UserSystemRoleRepository;
import com.energymonitor.security.adapter.out.persistence.support.Instants;
import com.energymonitor.security.application.port.out.UserSystemRolePersistencePort;
import com.energymonitor.security.domain.model.UserSystemRole;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for the {@code user_system_role} assignment.
 *
 * <p>The assignment is a composite-keyed row, so the key is the identity. Assigning again the
 * same pair cannot insert a second row, and it would fight the primary key to try. Instead,
 * when the row exists this adapter updates it, and when the row has been soft-deleted it
 * clears {@code deleted_at} - the reactivation strategy documented on the domain assignment.
 * An active row can never reach this path, because {@code assign} refuses to create a link
 * that already exists.
 */
@Component
public class UserSystemRolePersistenceAdapter implements UserSystemRolePersistencePort {

    private final UserSystemRoleRepository repository;
    private final UserSystemRoleMapper mapper;

    public UserSystemRolePersistenceAdapter(UserSystemRoleRepository repository,
            UserSystemRoleMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Saves an assignment: inserts a new row, or brings back a soft-deleted row with the same
     * pair of identifiers.
     *
     * @param assignment the domain object
     * @return the same domain object
     */
    public UserSystemRole save(UserSystemRole assignment) {
        UserSystemRoleId id = new UserSystemRoleId(assignment.idUser(), assignment.idSystemRole());
        UserSystemRoleEntity entity = repository.findById(id)
                .map(existing -> {
                    if (existing.getDeletedAt() != null) {
                        existing.setDeletedAt(null);
                    }
                    mapper.applyTo(existing, assignment);
                    return existing;
                })
                .orElseGet(() -> mapper.toEntity(assignment));
        repository.save(entity);
        return assignment;
    }

    /**
     * Soft-deletes the assignment between a user and a role.
     *
     * @param idUser        the user
     * @param idSystemRole  the role
     */
    public void remove(String idUser, String idSystemRole) {
        repository.findById(new UserSystemRoleId(idUser, idSystemRole))
                .ifPresent(entity -> {
                    entity.setDeletedAt(Instants.now());
                    repository.save(entity);
                });
    }

    /**
     * Finds the active assignment by its composite key.
     *
     * @param idUser       the user
     * @param idSystemRole the role
     * @return the assignment, empty when soft-deleted or missing
     */
    public Optional<UserSystemRole> findActive(String idUser, String idSystemRole) {
        return repository.findById(new UserSystemRoleId(idUser, idSystemRole))
                .filter(entity -> entity.getDeletedAt() == null)
                .map(mapper::toDomain);
    }

    /**
     * Lists the active roles assigned to a user.
     *
     * @param idUser the user
     * @return the assignments
     */
    public List<UserSystemRole> listActiveByUser(String idUser) {
        return repository.findByIdUserIdAndDeletedAtIsNull(idUser).stream()
                .map(mapper::toDomain)
                .toList();
    }

    /**
     * Lists the active members of a role.
     *
     * @param idSystemRole the role
     * @return the assignments
     */
    public List<UserSystemRole> listActiveBySystemRole(String idSystemRole) {
        return repository.findByIdSystemRoleIdAndDeletedAtIsNull(idSystemRole).stream()
                .map(mapper::toDomain)
                .toList();
    }
}