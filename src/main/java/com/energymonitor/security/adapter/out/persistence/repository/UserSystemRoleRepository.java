package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.UserSystemRoleEntity;
import com.energymonitor.security.adapter.out.persistence.entity.UserSystemRoleId;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code user_system_role}.
 *
 * <p>The composite key is the row identity, so {@code findById} deliberately sees soft-deleted
 * rows too: the reactivation strategy needs to load a deleted row in order to clear its
 * {@code deleted_at} and revive the assignment without fighting the primary key.
 */
@Repository
public interface UserSystemRoleRepository
        extends JpaRepository<UserSystemRoleEntity, UserSystemRoleId> {

    /**
     * Lists the active roles assigned to a user.
     *
     * <p>The property path goes through the embedded id ({@code id.userId}), because the
     * entity holds the pair in {@code @EmbeddedId} and owns no standalone {@code userId}
     * attribute.
     *
     * @param userId the user
     * @return the active assignments
     */
    List<UserSystemRoleEntity> findByIdUserIdAndDeletedAtIsNull(String userId);

    /**
     * Lists the active assignments of the given role, i.e. its current membership.
     *
     * @param systemRoleId the role
     * @return the active assignments
     */
    List<UserSystemRoleEntity> findByIdSystemRoleIdAndDeletedAtIsNull(String systemRoleId);
}