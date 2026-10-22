package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.PermissionEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code permission}.
 */
@Repository
public interface PermissionRepository extends JpaRepository<PermissionEntity, String> {

    /**
     * Lists the active permissions.
     *
     * @return the active rows
     */
    List<PermissionEntity> findByCodeIsNotNullAndDeletedAtIsNull();

    /**
     * Finds the active permission under the given code.
     *
     * @param code the stable permission code
     * @return the row, empty when soft-deleted or missing
     */
    Optional<PermissionEntity> findByCodeAndDeletedAtIsNull(String code);
}