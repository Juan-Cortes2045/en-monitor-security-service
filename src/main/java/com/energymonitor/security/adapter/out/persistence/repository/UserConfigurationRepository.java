package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.UserConfigurationEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code user_configuration}.
 */
@Repository
public interface UserConfigurationRepository extends JpaRepository<UserConfigurationEntity, String> {

    /**
     * Finds the active configuration of the given user.
     *
     * <p>One user keeps at most one configuration, so this query returns the single row the
     * unique constraint guarantees.
     *
     * @param userId the owner
     * @return the configuration, empty when soft-deleted or missing
     */
    Optional<UserConfigurationEntity> findByUserIdAndDeletedAtIsNull(String userId);
}