package com.energymonitor.security.adapter.out.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.domain.model.SystemRolePermission;
import com.energymonitor.security.domain.model.UserSystemRole;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

/**
 * Round trips of the two composite-keyed RBAC assignments.
 *
 * <p>The core behaviour under test is reactivation by key: after a soft delete, assigning the
 * same pair again clears {@code deleted_at} on the existing row instead of inserting a
 * duplicate, so the composite primary key is never violated and the graph stays one row.
 */
@SpringBootTest
@Transactional
class RbacAssignmentPersistenceTest extends JwtKeyedTest {

    private static final String USER_ID = "use0000001";
    private static final String ROLE_ID = "rls0000001";
    private static final String PERMISSION_ID = "prm0000001";
    private static final Instant ASSIGNED_AT = Instant.parse("2026-05-20T09:15:30Z");

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private PersonPersistenceAdapter persons;

    @Autowired
    private UserPersistenceAdapter users;

    @Autowired
    private SystemRolePersistenceAdapter systemRoles;

    @Autowired
    private PermissionPersistenceAdapter permissions;

    @Autowired
    private UserSystemRolePersistenceAdapter userSystemRole;

    @Autowired
    private SystemRolePermissionPersistenceAdapter systemRolePermission;

    private void flushAndClear() {
        entityManager.flush();
        entityManager.clear();
    }

    @Test
    void userSystemRoleInsertReactivationAndRemove() {
        PersistenceFixtures.seedUser(persons, users);
        PersistenceFixtures.seedRole(systemRoles);
        userSystemRole.save(new UserSystemRole(USER_ID, ROLE_ID, ASSIGNED_AT));
        flushAndClear();

        UserSystemRole read = userSystemRole.findActive(USER_ID, ROLE_ID).orElseThrow();
        assertEquals(USER_ID, read.idUser());
        assertEquals(ROLE_ID, read.idSystemRole());
        assertEquals(ASSIGNED_AT, read.assignedAt());

        userSystemRole.remove(USER_ID, ROLE_ID);
        flushAndClear();
        assertTrue(userSystemRole.findActive(USER_ID, ROLE_ID).isEmpty());
        assertTrue(userSystemRole.listActiveByUser(USER_ID).isEmpty());

        userSystemRole.save(new UserSystemRole(USER_ID, ROLE_ID, ASSIGNED_AT));
        flushAndClear();

        UserSystemRole reactivated = userSystemRole.findActive(USER_ID, ROLE_ID).orElseThrow();
        assertEquals(ASSIGNED_AT, reactivated.assignedAt());
        assertEquals(1, userSystemRole.listActiveByUser(USER_ID).size());
    }

    @Test
    void systemRolePermissionInsertReactivationAndRemove() {
        PersistenceFixtures.seedRole(systemRoles);
        PersistenceFixtures.seedPermission(permissions);
        systemRolePermission
                .save(new SystemRolePermission(ROLE_ID, PERMISSION_ID, ASSIGNED_AT));
        flushAndClear();

        SystemRolePermission read =
                systemRolePermission.findActive(ROLE_ID, PERMISSION_ID).orElseThrow();
        assertEquals(ROLE_ID, read.idSystemRole());
        assertEquals(PERMISSION_ID, read.idPermission());
        assertEquals(ASSIGNED_AT, read.assignedAt());

        systemRolePermission.remove(ROLE_ID, PERMISSION_ID);
        flushAndClear();
        assertTrue(systemRolePermission.findActive(ROLE_ID, PERMISSION_ID).isEmpty());
        assertTrue(systemRolePermission.listActiveBySystemRole(ROLE_ID).isEmpty());

        systemRolePermission
                .save(new SystemRolePermission(ROLE_ID, PERMISSION_ID, ASSIGNED_AT));
        flushAndClear();

        SystemRolePermission reactivated =
                systemRolePermission.findActive(ROLE_ID, PERMISSION_ID).orElseThrow();
        assertEquals(ASSIGNED_AT, reactivated.assignedAt());
        assertEquals(1, systemRolePermission.listActiveBySystemRole(ROLE_ID).size());
    }
}