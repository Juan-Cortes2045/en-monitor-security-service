package com.energymonitor.security.domain.model;

import java.util.Objects;
import java.util.Optional;

/**
 * A single authorizable action, identified by a stable code.
 *
 * <p>The code is the contract with the rest of the system and must stay stable so existing
 * grants keep working (INV-022). The human-readable name may change without consequence.
 *
 * <p>Maps to the {@code permission} table.
 */
public class Permission {

    private static final int CODE_MAX = 30;
    private static final int NAME_MAX = 50;
    private static final int DESCRIPTION_MAX = 100;

    private final String idPermission;
    private final String code;
    private String name;
    private String description;

    /**
     * @param idPermission identifier, {@code VARCHAR(10)}
     * @param code         stable, unique permission code
     * @param name         display name
     * @param description  optional description
     */
    public Permission(String idPermission, String code, String name, String description) {
        this.idPermission = Preconditions.text(idPermission, "idPermission");
        this.code = Preconditions.text(code, CODE_MAX, "code");
        this.name = Preconditions.text(name, NAME_MAX, "name");
        this.description = Preconditions.optionalText(description, DESCRIPTION_MAX, "description");
    }

    /** @return the identifier */
    public String idPermission() {
        return idPermission;
    }

    /** @return the stable code */
    public String code() {
        return code;
    }

    /** @return the display name */
    public String name() {
        return name;
    }

    /** @return the description, empty when not provided */
    public Optional<String> description() {
        return Optional.ofNullable(description);
    }

    /**
     * Replaces the display name. The code never changes, it is the stable contract (INV-022).
     *
     * @param name new display name
     */
    public void rename(String name) {
        this.name = Preconditions.text(name, NAME_MAX, "name");
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
        if (!(other instanceof Permission that)) {
            return false;
        }
        return idPermission.equals(that.idPermission);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idPermission);
    }

    @Override
    public String toString() {
        return "Permission{idPermission='" + idPermission + "', code='" + code + "'}";
    }
}
