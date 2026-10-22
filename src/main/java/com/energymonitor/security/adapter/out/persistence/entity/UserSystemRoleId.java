package com.energymonitor.security.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;

/**
 * Primary key of the {@code user_system_role} table: {@code (user_id, system_role_id)}.
 *
 * <p>Purely a persistence concern. The composite key is an implementation detail of the
 * {@code user_system_role} table and never travels into the domain, where
 * {@code UserSystemRole} identifies the assignment by the same two identifiers but is not
 * modelled as a JPA identifier.
 */
@Embeddable
public class UserSystemRoleId implements Serializable {

    @Column(name = "user_id", nullable = false, length = 10)
    private String userId;

    @Column(name = "system_role_id", nullable = false, length = 10)
    private String systemRoleId;

    /**
     * Required by JPA.
     */
    public UserSystemRoleId() {
    }

    public UserSystemRoleId(String userId, String systemRoleId) {
        this.userId = userId;
        this.systemRoleId = systemRoleId;
    }

    public String getUserId() {
        return userId;
    }

    public String getSystemRoleId() {
        return systemRoleId;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof UserSystemRoleId that)) {
            return false;
        }
        return Objects.equals(userId, that.userId) && Objects.equals(systemRoleId, that.systemRoleId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, systemRoleId);
    }

    @Override
    public String toString() {
        return "UserSystemRoleId{userId='" + userId + "', systemRoleId='" + systemRoleId + "'}";
    }
}
