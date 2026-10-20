package com.energymonitor.security.domain.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Assignment of a global {@link SystemRole} to a {@link User}.
 *
 * <p>A many-to-many link. A user may hold several roles, but the same pair exists only once:
 * that uniqueness is the composite primary key {@code pk_user_system_role} (INV-021).
 *
 * <p>Holds identifiers only. It is a link, not an owner, so it does not keep live references
 * to the user or the role.
 *
 * <p>Maps to the {@code user_system_role} table.
 *
 * <p><strong>Pending, for the persistence phase.</strong> The table carries {@code deleted_at}
 * but its primary key is the {@code (user_id, system_role_id)} pair. A soft-deleted row
 * therefore still occupies the primary key, so re-assigning a revoked role would collide on
 * insert. The decided strategy is <em>reactivation</em>: the repository looks the pair up
 * including soft-deleted rows, and assigning again clears {@code deleted_at} instead of
 * inserting a duplicate. The alternative, refusing to reuse a revoked pair, was rejected
 * because removing and re-granting a role is an ordinary RBAC operation. Nothing in this
 * class implements that yet; it belongs to the repository, not to the domain.
 */
public class UserSystemRole {

    private final String idUser;
    private final String idSystemRole;
    private final Instant assignedAt;

    /**
     * @param idUser       identifier of the user
     * @param idSystemRole identifier of the role
     * @param assignedAt   when the role was granted
     */
    public UserSystemRole(String idUser, String idSystemRole, Instant assignedAt) {
        this.idUser = Preconditions.text(idUser, "idUser");
        this.idSystemRole = Preconditions.text(idSystemRole, "idSystemRole");
        this.assignedAt = Preconditions.notNull(assignedAt, "assignedAt");
    }

    /**
     * Grants a role to a user.
     *
     * @param user       the user receiving the role
     * @param systemRole the role being granted
     * @param assignedAt when it is granted
     * @return the new assignment
     * @throws IllegalStateException if the role is disabled (INV-019)
     */
    public static UserSystemRole assign(User user, SystemRole systemRole, Instant assignedAt) {
        Preconditions.notNull(user, "user");
        Preconditions.notNull(systemRole, "systemRole");
        if (!systemRole.canBeAssigned()) {
            throw new IllegalStateException("role " + systemRole.name() + " is disabled and cannot be assigned");
        }
        return new UserSystemRole(user.idUser(), systemRole.idSystemRole(), assignedAt);
    }

    /** @return identifier of the user */
    public String idUser() {
        return idUser;
    }

    /** @return identifier of the role */
    public String idSystemRole() {
        return idSystemRole;
    }

    /** @return when the role was granted */
    public Instant assignedAt() {
        return assignedAt;
    }

    /**
     * Whether this assignment links the given user to the given role.
     *
     * @param user       user identifier to test
     * @param systemRole role identifier to test
     * @return {@code true} when both match
     */
    public boolean links(String user, String systemRole) {
        return idUser.equals(user) && idSystemRole.equals(systemRole);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof UserSystemRole that)) {
            return false;
        }
        return idUser.equals(that.idUser) && idSystemRole.equals(that.idSystemRole);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idUser, idSystemRole);
    }

    @Override
    public String toString() {
        return "UserSystemRole{idUser='" + idUser + "', idSystemRole='" + idSystemRole + "'}";
    }
}
