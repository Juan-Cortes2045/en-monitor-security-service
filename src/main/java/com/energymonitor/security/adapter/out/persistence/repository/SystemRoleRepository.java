package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.SystemRoleEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code system_role}.
 */
@Repository
public interface SystemRoleRepository extends JpaRepository<SystemRoleEntity, String> {

    /**
     * Lists the active roles.
     *
     * @return the active rows
     */
    List<SystemRoleEntity> findByDeletedAtIsNull();

    /**
     * Finds the active role under the given name.
     *
     * @param name the role name
     * @return the row, empty when soft-deleted or missing
     */
    Optional<SystemRoleEntity> findByNameAndDeletedAtIsNull(String name);
}