package com.energymonitor.security.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * JPA mapping of the {@code system_role} table.
 */
@Entity
@Table(name = "system_role")
public class SystemRoleEntity extends BaseAuditEntity {

    @Id
    @Column(name = "id_system_role", nullable = false, length = 10)
    private String idSystemRole;

    @Column(name = "name", nullable = false, length = 50)
    private String name;

    @Column(name = "description", length = 200)
    private String description;

    @Column(name = "enabled", nullable = false)
    @TinyIntBoolean
    private boolean enabled;

    public SystemRoleEntity() {
    }

    public String getIdSystemRole() {
        return idSystemRole;
    }

    public void setIdSystemRole(String idSystemRole) {
        this.idSystemRole = idSystemRole;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
