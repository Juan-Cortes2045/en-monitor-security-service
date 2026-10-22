package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordHash;
import com.energymonitor.security.domain.model.Permission;
import com.energymonitor.security.domain.model.Person;
import com.energymonitor.security.domain.model.SystemRole;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Instant;

/**
 * Shared seeds for persistence tests.
 *
 * <p>The tables referenced by foreign keys ({@code person}, {@code user}, {@code system_role},
 * {@code permission}) have to exist before a child row can be inserted. These helpers plant
 * them through the adapters, inside the caller's transaction, so the whole graph rolls back
 * with the test.
 */
final class PersistenceFixtures {

    static final String PERSON_ID = "per0000001";
    static final String USER_ID = "use0000001";
    static final String ROLE_ID = "rls0000001";
    static final String PERMISSION_ID = "prm0000001";
    static final String HASH =
            "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static final Instant REGISTRATION = Instant.parse("2026-01-02T03:04:05Z");

    private PersistenceFixtures() {
    }

    static void seedPerson(PersonPersistenceAdapter persons) {
        persons.save(new Person(PERSON_ID, "Ada", "Lovelace"));
    }

    /** Seeds {@code person} and {@code user}, the two roots most rows depend on. */
    static void seedUser(PersonPersistenceAdapter persons, UserPersistenceAdapter users) {
        seedPerson(persons);
        users.save(new User(USER_ID, PERSON_ID, PasswordHash.of(HASH),
                Email.of("ada@example.com"), true, REGISTRATION, UserStatus.ACTIVE, 0, null, null));
    }

    /** Seeds the role a grant and an assignment can point at. */
    static void seedRole(SystemRolePersistenceAdapter systemRoles) {
        systemRoles.save(new SystemRole(ROLE_ID, "ROLE_ADMIN", "Administrators", true));
    }

    /** Seeds the permission a grant can point at. */
    static void seedPermission(PermissionPersistenceAdapter permissions) {
        permissions.save(new Permission(PERMISSION_ID, "METER.READ", "Read meters", null));
    }
}