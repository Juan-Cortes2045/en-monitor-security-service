package com.energymonitor.security.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;

/**
 * Primary key of the {@code system_role_permission} table:
 * {@code (system_role_id, permission_id)}.
 *
 * <p>Purely a persistence concern, for the same reason as {@link UserSystemRoleId}.
 */
@Embeddable
public class SystemRolePermissionId implements Serializable {

    @Column(name = "system_role_id", nullable = false, length = 10)
    private String systemRoleId;

    @Column(name = "permission_id", nullable = false, length = 10)
    private String permissionId;

    /**
     * Required by JPA.
     */
    public SystemRolePermissionId() {
    }

    public SystemRolePermissionId(String systemRoleId, String permissionId) {
        this.systemRoleId = systemRoleId;
        this.permissionId = permissionId;
    }

    public String getSystemRoleId() {
        return systemRoleId;
    }

    public String getPermissionId() {
        return permissionId;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof SystemRolePermissionId that)) {
            return false;
        }
        return Objects.equals(systemRoleId, that.systemRoleId)
                && Objects.equals(permissionId, that.permissionId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(systemRoleId, permissionId);
    }

    @Override
    public String toString() {
        return "SystemRolePermissionId{systemRoleId='" + systemRoleId + "', permissionId='"
                + permissionId + "'}";
    }
}
