package com.energymonitor.security.domain.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Grant of a {@link Permission} to a {@link SystemRole}.
 *
 * <p>The second half of the RBAC chain: {@code User → UserSystemRole → SystemRole →
 * SystemRolePermission → Permission}. A role may hold several permissions, and the same pair
 * exists only once, enforced by the composite primary key {@code pk_system_role_permission}.
 *
 * <p>Maps to the {@code system_role_permission} table.
 *
 * <p><strong>Pending, for the persistence phase.</strong> Same situation as
 * {@link UserSystemRole}: the table has {@code deleted_at} but its primary key is the
 * {@code (system_role_id, permission_id)} pair, so a soft-deleted grant still occupies the
 * key. The decided strategy is <em>reactivation</em>: granting again clears {@code deleted_at}
 * on the existing row rather than inserting a duplicate, because narrowing and widening a
 * role is an ordinary operation. It is not implemented here; it belongs to the repository.
 */
public class SystemRolePermission {

    private final String idSystemRole;
    private final String idPermission;
    private final Instant assignedAt;

    /**
     * @param idSystemRole identifier of the role
     * @param idPermission identifier of the permission
     * @param assignedAt   when the permission was granted
     */
    public SystemRolePermission(String idSystemRole, String idPermission, Instant assignedAt) {
        this.idSystemRole = Preconditions.text(idSystemRole, "idSystemRole");
        this.idPermission = Preconditions.text(idPermission, "idPermission");
        this.assignedAt = Preconditions.notNull(assignedAt, "assignedAt");
    }

    /**
     * Grants a permission to a role.
     *
     * @param systemRole the role receiving the permission
     * @param permission the permission being granted
     * @param assignedAt when it is granted
     * @return the new grant
     */
    public static SystemRolePermission grant(SystemRole systemRole, Permission permission, Instant assignedAt) {
        Preconditions.notNull(systemRole, "systemRole");
        Preconditions.notNull(permission, "permission");
        return new SystemRolePermission(systemRole.idSystemRole(), permission.idPermission(), assignedAt);
    }

    /** @return identifier of the role */
    public String idSystemRole() {
        return idSystemRole;
    }

    /** @return identifier of the permission */
    public String idPermission() {
        return idPermission;
    }

    /** @return when the permission was granted */
    public Instant assignedAt() {
        return assignedAt;
    }

    /**
     * Whether this grant links the given role to the given permission.
     *
     * @param systemRole role identifier to test
     * @param permission permission identifier to test
     * @return {@code true} when both match
     */
    public boolean links(String systemRole, String permission) {
        return idSystemRole.equals(systemRole) && idPermission.equals(permission);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof SystemRolePermission that)) {
            return false;
        }
        return idSystemRole.equals(that.idSystemRole) && idPermission.equals(that.idPermission);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idSystemRole, idPermission);
    }

    @Override
    public String toString() {
        return "SystemRolePermission{idSystemRole='" + idSystemRole + "', idPermission='" + idPermission + "'}";
    }
}
