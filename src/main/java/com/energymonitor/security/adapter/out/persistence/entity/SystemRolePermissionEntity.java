package com.energymonitor.security.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * JPA mapping of the {@code system_role_permission} table.
 *
 * <p>Same shape as {@link UserSystemRoleEntity}: a composite primary key held in an embedded
 * id, and no implicit filtering of soft-deleted rows so that the reactivation strategy can
 * find and revive them.
 */
@Entity
@Table(name = "system_role_permission")
public class SystemRolePermissionEntity extends BaseAuditEntity {

    @EmbeddedId
    private SystemRolePermissionId id;

    @Column(name = "assigned_at", nullable = false)
    private Instant assignedAt;

    public SystemRolePermissionEntity() {
    }

    public SystemRolePermissionEntity(SystemRolePermissionId id, Instant assignedAt) {
        this.id = id;
        this.assignedAt = assignedAt;
    }

    public SystemRolePermissionId getId() {
        return id;
    }

    public void setId(SystemRolePermissionId id) {
        this.id = id;
    }

    /** @return role identifier, part of the primary key */
    public String getSystemRoleId() {
        return id == null ? null : id.getSystemRoleId();
    }

    /** @return permission identifier, part of the primary key */
    public String getPermissionId() {
        return id == null ? null : id.getPermissionId();
    }

    public Instant getAssignedAt() {
        return assignedAt;
    }

    public void setAssignedAt(Instant assignedAt) {
        this.assignedAt = assignedAt;
    }
}
