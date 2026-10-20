package com.energymonitor.security.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * JPA mapping of the {@code user_system_role} table.
 *
 * <p>The identifier is the {@code (user_id, system_role_id)} pair declared by changeset
 * {@code security-011}. Both columns therefore live in the {@link UserSystemRoleId} embedded
 * id rather than being repeated as ordinary attributes: they are the primary key, and
 * declaring them twice would invite a mismatch between the key and the value.
 *
 * <p>Because the pair is the primary key, a soft-deleted row still occupies it. That is why
 * this entity has no {@code @SQLRestriction} hiding deleted rows: the reactivation strategy
 * documented on the domain {@code UserSystemRole} needs to load a deleted row in order to
 * clear {@code deleted_at} and revive it. Filtering is left to the repository methods, which
 * state their intent explicitly.
 */
@Entity
@Table(name = "user_system_role")
public class UserSystemRoleEntity extends BaseAuditEntity {

    @EmbeddedId
    private UserSystemRoleId id;

    @Column(name = "assigned_at", nullable = false)
    private Instant assignedAt;

    public UserSystemRoleEntity() {
    }

    public UserSystemRoleEntity(UserSystemRoleId id, Instant assignedAt) {
        this.id = id;
        this.assignedAt = assignedAt;
    }

    public UserSystemRoleId getId() {
        return id;
    }

    public void setId(UserSystemRoleId id) {
        this.id = id;
    }

    /** @return user identifier, part of the primary key */
    public String getUserId() {
        return id == null ? null : id.getUserId();
    }

    /** @return role identifier, part of the primary key */
    public String getSystemRoleId() {
        return id == null ? null : id.getSystemRoleId();
    }

    public Instant getAssignedAt() {
        return assignedAt;
    }

    public void setAssignedAt(Instant assignedAt) {
        this.assignedAt = assignedAt;
    }
}
