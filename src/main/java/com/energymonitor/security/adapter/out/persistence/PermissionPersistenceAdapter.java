package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.PermissionEntity;
import com.energymonitor.security.adapter.out.persistence.mapper.PermissionMapper;
import com.energymonitor.security.adapter.out.persistence.repository.PermissionRepository;
import com.energymonitor.security.application.port.out.PermissionPersistencePort;
import com.energymonitor.security.domain.model.Permission;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for {@link Permission}.
 */
@Component
public class PermissionPersistenceAdapter implements PermissionPersistencePort {

    private final PermissionRepository repository;
    private final PermissionMapper mapper;

    public PermissionPersistenceAdapter(PermissionRepository repository, PermissionMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Inserts or updates the permission.
     *
     * @param permission the domain object
     * @return the same domain object
     */
    public Permission save(Permission permission) {
        PermissionEntity entity = repository.findById(permission.idPermission())
                .map(existing -> {
                    mapper.applyTo(existing, permission);
                    return existing;
                })
                .orElseGet(() -> mapper.toEntity(permission));
        repository.save(entity);
        return permission;
    }

    /**
     * Finds the active permission by identifier.
     *
     * @param idPermission the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    public Optional<Permission> findActive(String idPermission) {
        return repository.findById(idPermission)
                .filter(entity -> entity.getDeletedAt() == null)
                .map(mapper::toDomain);
    }

    /**
     * Finds the active permission by code.
     *
     * @param code the stable permission code
     * @return the domain object, empty when soft-deleted or missing
     */
    public Optional<Permission> findActiveByCode(String code) {
        return repository.findByCodeAndDeletedAtIsNull(code)
                .map(mapper::toDomain);
    }

    /**
     * Lists the active permissions.
     *
     * @return the active permissions
     */
    public List<Permission> findAllActive() {
        return repository.findByCodeIsNotNullAndDeletedAtIsNull().stream()
                .map(mapper::toDomain)
                .toList();
    }
}