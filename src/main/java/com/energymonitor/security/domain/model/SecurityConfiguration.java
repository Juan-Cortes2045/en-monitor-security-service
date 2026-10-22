package com.energymonitor.security.domain.model;

import java.util.Objects;
import java.util.Optional;

/**
 * System-wide security setting expressed as a name/value pair.
 *
 * <p>Belongs to the system, not to a user (INV-014). The value is stored as text so a new
 * setting can be introduced without a schema change; interpreting it is the application's
 * job.
 *
 * <p>Maps to the {@code security_configuration} table.
 */
public class SecurityConfiguration {

    private static final int NAME_MAX = 100;
    private static final int VALUE_MAX = 100;
    private static final int DESCRIPTION_MAX = 255;

    private final String idSecurityConfiguration;
    private final String configName;
    private String configValue;
    private String description;

    /**
     * @param idSecurityConfiguration identifier, {@code VARCHAR(10)}
     * @param configName              unique setting name
     * @param configValue             setting value, as text
     * @param description             optional description
     */
    public SecurityConfiguration(String idSecurityConfiguration, String configName,
                                 String configValue, String description) {
        this.idSecurityConfiguration = Preconditions.text(idSecurityConfiguration, "idSecurityConfiguration");
        this.configName = Preconditions.text(configName, NAME_MAX, "configName");
        this.configValue = Preconditions.text(configValue, VALUE_MAX, "configValue");
        this.description = Preconditions.optionalText(description, DESCRIPTION_MAX, "description");
    }

    /** @return the identifier */
    public String idSecurityConfiguration() {
        return idSecurityConfiguration;
    }

    /** @return the setting name */
    public String configName() {
        return configName;
    }

    /** @return the setting value as text */
    public String configValue() {
        return configValue;
    }

    /** @return the description, empty when not provided */
    public Optional<String> description() {
        return Optional.ofNullable(description);
    }

    /**
     * Replaces the setting value.
     *
     * @param configValue new value, required
     */
    public void changeValue(String configValue) {
        this.configValue = Preconditions.text(configValue, VALUE_MAX, "configValue");
    }

    /**
     * Replaces the description. Passing {@code null} clears it.
     *
     * @param description new description or {@code null}
     */
    public void changeDescription(String description) {
        this.description = Preconditions.optionalText(description, DESCRIPTION_MAX, "description");
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof SecurityConfiguration that)) {
            return false;
        }
        return idSecurityConfiguration.equals(that.idSecurityConfiguration);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idSecurityConfiguration);
    }

    @Override
    public String toString() {
        return "SecurityConfiguration{idSecurityConfiguration='" + idSecurityConfiguration
                + "', configName='" + configName + "'}";
    }
}
