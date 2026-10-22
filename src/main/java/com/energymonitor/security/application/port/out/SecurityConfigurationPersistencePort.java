package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.SecurityConfiguration;
import java.util.Optional;

/**
 * Output port for system-wide {@link SecurityConfiguration} entries.
 *
 * <p>Settings are stored as name/value text, which the domain deliberately leaves
 * uninterpreted: reading a value and deciding what it means is application work, so this port
 * hands back the domain object and never a parsed number or a flag derived from a column.
 *
 * <p>Lookup by name is the operation that carries the application's need, because settings are
 * addressed by the key they are known by rather than by an identifier allocated at write time.
 * Reading {@code lockout.max_attempts} to decide when to block an account is the first
 * intended consumer.
 */
public interface SecurityConfigurationPersistencePort {

    /**
     * Inserts or updates the setting entry.
     *
     * <p>The write side is part of the port because these rows cannot be created any other way:
     * they are not user data and the schema ships no seed data, so provisioning a setting is
     * an application decision rather than a migration.
     *
     * @param configuration the domain object
     * @return the same domain object
     */
    SecurityConfiguration save(SecurityConfiguration configuration);

    /**
     * Finds the active entry by identifier.
     *
     * @param idSecurityConfiguration the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    Optional<SecurityConfiguration> findActive(String idSecurityConfiguration);

    /**
     * Finds the active entry under a configuration name.
     *
     * @param configName the configuration key
     * @return the domain object, empty when soft-deleted or missing
     */
    Optional<SecurityConfiguration> findActiveByName(String configName);
}
