package com.energymonitor.security.domain.model;

import java.util.Objects;
import java.util.Optional;

/**
 * Global RBAC role that groups permissions across the whole platform.
 *
 * <p>Not to be confused with the home-scoped role of the Home Management context: this one is
 * global and its name is unique platform-wide (INV-020).
 *
 * <p>Maps to the {@code system_role} table.
 */
public class SystemRole {

    private static final int NAME_MAX = 50;
    private static final int DESCRIPTION_MAX = 200;

    private final String idSystemRole;
    private final String name;
    private String description;
    private boolean enabled;

    /**
     * @param idSystemRole identifier, {@code VARCHAR(10)}
     * @param name         unique role name
     * @param description  optional description
     * @param enabled      whether the role is active
     */
    public SystemRole(String idSystemRole, String name, String description, boolean enabled) {
        this.idSystemRole = Preconditions.text(idSystemRole, "idSystemRole");
        this.name = Preconditions.text(name, NAME_MAX, "name");
        this.description = Preconditions.optionalText(description, DESCRIPTION_MAX, "description");
        this.enabled = enabled;
    }

    /** @return the identifier */
    public String idSystemRole() {
        return idSystemRole;
    }

    /** @return the role name */
    public String name() {
        return name;
    }

    /** @return the description, empty when not provided */
    public Optional<String> description() {
        return Optional.ofNullable(description);
    }

    /** @return whether the role is active */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Whether this role may be assigned to a user (INV-019).
     *
     * @return {@code true} when the role is enabled
     */
    public boolean canBeAssigned() {
        return enabled;
    }

    /** Enables the role so it can be assigned again. */
    public void enable() {
        this.enabled = true;
    }

    /** Disables the role. It stops being assignable to new users (INV-019). */
    public void disable() {
        this.enabled = false;
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
        if (!(other instanceof SystemRole that)) {
            return false;
        }
        return idSystemRole.equals(that.idSystemRole);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idSystemRole);
    }

    @Override
    public String toString() {
        return "SystemRole{idSystemRole='" + idSystemRole + "', name='" + name + "', enabled=" + enabled + "}";
    }
}
