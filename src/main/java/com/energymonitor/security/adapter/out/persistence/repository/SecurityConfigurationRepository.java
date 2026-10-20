package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.SecurityConfigurationEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code security_configuration}.
 */
@Repository
public interface SecurityConfigurationRepository
        extends JpaRepository<SecurityConfigurationEntity, String> {

    /**
     * Finds the active configuration entry under the given name.
     *
     * @param configName the configuration key
     * @return the row, empty when soft-deleted or missing
     */
    Optional<SecurityConfigurationEntity> findByConfigNameAndDeletedAtIsNull(String configName);
}