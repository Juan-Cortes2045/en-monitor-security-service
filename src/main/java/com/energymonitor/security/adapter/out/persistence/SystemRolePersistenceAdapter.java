package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.SystemRoleEntity;
import com.energymonitor.security.adapter.out.persistence.mapper.SystemRoleMapper;
import com.energymonitor.security.adapter.out.persistence.repository.SystemRoleRepository;
import com.energymonitor.security.application.port.out.SystemRolePersistencePort;
import com.energymonitor.security.domain.model.SystemRole;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for {@link SystemRole}.
 */
@Component
public class SystemRolePersistenceAdapter implements SystemRolePersistencePort {

    private final SystemRoleRepository repository;
    private final SystemRoleMapper mapper;

    public SystemRolePersistenceAdapter(SystemRoleRepository repository, SystemRoleMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Inserts or updates the role.
     *
     * @param role the domain object
     * @return the same domain object
     */
    public SystemRole save(SystemRole role) {
        SystemRoleEntity entity = repository.findById(role.idSystemRole())
                .map(existing -> {
                    mapper.applyTo(existing, role);
                    return existing;
                })
                .orElseGet(() -> mapper.toEntity(role));
        repository.save(entity);
        return role;
    }

    /**
     * Finds the active role by identifier.
     *
     * @param idSystemRole the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    public Optional<SystemRole> findActive(String idSystemRole) {
        return repository.findById(idSystemRole)
                .filter(entity -> entity.getDeletedAt() == null)
                .map(mapper::toDomain);
    }

    /**
     * Finds the active role by name.
     *
     * @param name the role name
     * @return the domain object, empty when soft-deleted or missing
     */
    public Optional<SystemRole> findActiveByName(String name) {
        return repository.findByNameAndDeletedAtIsNull(name)
                .map(mapper::toDomain);
    }

    /**
     * Lists the active roles.
     *
     * @return the active roles
     */
    public List<SystemRole> findAllActive() {
        return repository.findByDeletedAtIsNull().stream()
                .map(mapper::toDomain)
                .toList();
    }
}