package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.SystemRolePermissionEntity;
import com.energymonitor.security.adapter.out.persistence.entity.SystemRolePermissionId;
import com.energymonitor.security.adapter.out.persistence.mapper.SystemRolePermissionMapper;
import com.energymonitor.security.adapter.out.persistence.repository.SystemRolePermissionRepository;
import com.energymonitor.security.adapter.out.persistence.support.Instants;
import com.energymonitor.security.application.port.out.SystemRolePermissionPersistencePort;
import com.energymonitor.security.domain.model.SystemRolePermission;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for the {@code system_role_permission} grant.
 *
 * <p>Mirror of {@link UserSystemRolePersistenceAdapter}: the composite key is the identity,
 * so granting the same pair again reactivates a soft-deleted row instead of inserting a
 * duplicate.
 */
@Component
public class SystemRolePermissionPersistenceAdapter implements SystemRolePermissionPersistencePort {

    private final SystemRolePermissionRepository repository;
    private final SystemRolePermissionMapper mapper;

    public SystemRolePermissionPersistenceAdapter(SystemRolePermissionRepository repository,
            SystemRolePermissionMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Saves a grant: inserts a new row, or brings back a soft-deleted row with the same pair
     * of identifiers.
     *
     * @param grant the domain object
     * @return the same domain object
     */
    public SystemRolePermission save(SystemRolePermission grant) {
        SystemRolePermissionId id =
                new SystemRolePermissionId(grant.idSystemRole(), grant.idPermission());
        SystemRolePermissionEntity entity = repository.findById(id)
                .map(existing -> {
                    if (existing.getDeletedAt() != null) {
                        existing.setDeletedAt(null);
                    }
                    mapper.applyTo(existing, grant);
                    return existing;
                })
                .orElseGet(() -> mapper.toEntity(grant));
        repository.save(entity);
        return grant;
    }

    /**
     * Soft-deletes the grant between a role and a permission.
     *
     * @param idSystemRole the role
     * @param idPermission the permission
     */
    public void remove(String idSystemRole, String idPermission) {
        repository.findById(new SystemRolePermissionId(idSystemRole, idPermission))
                .ifPresent(entity -> {
                    entity.setDeletedAt(Instants.now());
                    repository.save(entity);
                });
    }

    /**
     * Finds the active grant by its composite key.
     *
     * @param idSystemRole the role
     * @param idPermission the permission
     * @return the grant, empty when soft-deleted or missing
     */
    public Optional<SystemRolePermission> findActive(String idSystemRole, String idPermission) {
        return repository.findById(new SystemRolePermissionId(idSystemRole, idPermission))
                .filter(entity -> entity.getDeletedAt() == null)
                .map(mapper::toDomain);
    }

    /**
     * Lists the active permissions granted to a role.
     *
     * @param idSystemRole the role
     * @return the grants
     */
    public List<SystemRolePermission> listActiveBySystemRole(String idSystemRole) {
        return repository.findByIdSystemRoleIdAndDeletedAtIsNull(idSystemRole).stream()
                .map(mapper::toDomain)
                .toList();
    }

    /**
     * Lists the active roles holding a permission.
     *
     * @param idPermission the permission
     * @return the grants
     */
    public List<SystemRolePermission> listActiveByPermission(String idPermission) {
        return repository.findByIdPermissionIdAndDeletedAtIsNull(idPermission).stream()
                .map(mapper::toDomain)
                .toList();
    }
}