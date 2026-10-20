package com.energymonitor.security.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * JPA mapping of the {@code security_configuration} table.
 */
@Entity
@Table(name = "security_configuration")
public class SecurityConfigurationEntity extends BaseAuditEntity {

    @Id
    @Column(name = "id_security_configuration", nullable = false, length = 10)
    private String idSecurityConfiguration;

    @Column(name = "config_name", nullable = false, length = 100)
    private String configName;

    @Column(name = "config_value", nullable = false, length = 100)
    private String configValue;

    @Column(name = "description", length = 255)
    private String description;

    public SecurityConfigurationEntity() {
    }

    public String getIdSecurityConfiguration() {
        return idSecurityConfiguration;
    }

    public void setIdSecurityConfiguration(String idSecurityConfiguration) {
        this.idSecurityConfiguration = idSecurityConfiguration;
    }

    public String getConfigName() {
        return configName;
    }

    public void setConfigName(String configName) {
        this.configName = configName;
    }

    public String getConfigValue() {
        return configValue;
    }

    public void setConfigValue(String configValue) {
        this.configValue = configValue;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
