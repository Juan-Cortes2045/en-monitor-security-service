package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.SystemRolePermissionEntity;
import com.energymonitor.security.adapter.out.persistence.entity.SystemRolePermissionId;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code system_role_permission}.
 *
 * <p>Like {@link UserSystemRoleRepository}, {@code findById} intentionally sees soft-deleted
 * rows so the reactivation strategy can revive a taken-away grant.
 */
@Repository
public interface SystemRolePermissionRepository
        extends JpaRepository<SystemRolePermissionEntity, SystemRolePermissionId> {

    /**
     * Lists the active permissions granted to a role.
     *
     * <p>The property path goes through the embedded id ({@code id.systemRoleId}).
     *
     * @param systemRoleId the role
     * @return the active grants
     */
    List<SystemRolePermissionEntity> findByIdSystemRoleIdAndDeletedAtIsNull(String systemRoleId);

    /**
     * Lists the active roles granted the given permission.
     *
     * @param permissionId the permission
     * @return the active grants
     */
    List<SystemRolePermissionEntity> findByIdPermissionIdAndDeletedAtIsNull(String permissionId);
}