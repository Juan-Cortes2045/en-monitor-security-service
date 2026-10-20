package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.UserConfiguration;
import java.util.Optional;

/**
 * Output port for the per-user {@link UserConfiguration} preferences.
 *
 * <p>Preferences are owned by a user and are looked up by that user rather than by an
 * identifier allocated at write time, so lookup by user is the operation the application
 * needs. Exactly one configuration is expected per user.
 */
public interface UserConfigurationPersistencePort {

    /**
     * Inserts or updates the user's configuration.
     *
     * <p>The write side is part of the port because these rows are created by the application
     * when an account is provisioned, and the schema ships no seed data.
     *
     * @param configuration the domain object
     * @return the same domain object
     */
    UserConfiguration save(UserConfiguration configuration);

    /**
     * Finds the active configuration by identifier.
     *
     * @param idConfiguration the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    Optional<UserConfiguration> findActive(String idConfiguration);

    /**
     * Finds the active configuration belonging to a user.
     *
     * @param idUser the owning user identifier
     * @return the domain object, empty when soft-deleted or absent
     */
    Optional<UserConfiguration> findActiveByUser(String idUser);
}
