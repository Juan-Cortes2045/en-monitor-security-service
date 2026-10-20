package com.energymonitor.security.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.command.AssignRoleCommand;
import com.energymonitor.security.application.command.CheckPermissionQuery;
import com.energymonitor.security.application.command.RevokeRoleCommand;
import com.energymonitor.security.application.exception.RoleNotFoundException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.usecase.AssignRoleService;
import com.energymonitor.security.application.usecase.CheckPermissionService;
import com.energymonitor.security.application.usecase.RevokeRoleService;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.Permission;
import com.energymonitor.security.domain.model.SystemRole;
import com.energymonitor.security.domain.model.SystemRolePermission;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The RBAC trio {@code AssignRole}, {@code RevokeRole} and {@code CheckPermission}: granting
 * and revoking are audited, and the permission check walks the enabled-role chain.
 */
class RbacServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-03-01T12:00:00Z"), ZoneOffset.UTC);

    private final UseCaseFixtures.FakeUserPersistencePort users = new UseCaseFixtures.FakeUserPersistencePort();
    private final UseCaseFixtures.FakeSystemRolePersistencePort roles = new UseCaseFixtures.FakeSystemRolePersistencePort();
    private final UseCaseFixtures.FakePermissionPersistencePort permissions =
            new UseCaseFixtures.FakePermissionPersistencePort();
    private final UseCaseFixtures.FakeUserSystemRolePersistencePort assignments =
            new UseCaseFixtures.FakeUserSystemRolePersistencePort();
    private final UseCaseFixtures.FakeSystemRolePermissionPersistencePort grants =
            new UseCaseFixtures.FakeSystemRolePermissionPersistencePort();
    private final UseCaseFixtures.FakeAuditLogPersistencePort audits = new UseCaseFixtures.FakeAuditLogPersistencePort();
    private final UseCaseFixtures.FakeIdentifierGeneratorPort identifiers =
            new UseCaseFixtures.FakeIdentifierGeneratorPort();
    private final AssignRoleService assignRole =
            new AssignRoleService(users, roles, assignments, audits, identifiers, CLOCK);
    private final RevokeRoleService revokeRole = new RevokeRoleService(assignments, audits, identifiers, CLOCK);
    private final CheckPermissionService checkPermission =
            new CheckPermissionService(users, permissions, roles, assignments, grants);

    @Test
    void assignsAUserRoleAndAuditsIt() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        roles.seed("rls0000001", "ROLE_ADMIN", true);

        assignRole.assign(new AssignRoleCommand("use0000001", "rls0000001", "10.0.0.2"));

        assertTrue(assignments.findActive("use0000001", "rls0000001").isPresent());
        assertEquals(AuditAction.CREATE, audits.logs().getFirst().action());
    }

    @Test
    void assigningTheSameRoleTwiceIsIdempotent() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        roles.seed("rls0000001", "ROLE_ADMIN", true);

        assignRole.assign(new AssignRoleCommand("use0000001", "rls0000001", null));
        assignRole.assign(new AssignRoleCommand("use0000001", "rls0000001", null));

        assertEquals(1, assignments.listActiveByUser("use0000001").size());
    }

    @Test
    void refusesToAssignADisabledRole() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        roles.seed("rls0000001", "ROLE_ADMIN", false);

        assertThrows(IllegalStateException.class,
                () -> assignRole.assign(new AssignRoleCommand("use0000001", "rls0000001", null)));
    }

    @Test
    void assigningAnUnknownRoleFails() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);

        assertThrows(RoleNotFoundException.class,
                () -> assignRole.assign(new AssignRoleCommand("use0000001", "ghost", null)));
    }

    @Test
    void revokesAnAssignmentAndAuditsTheDelete() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        roles.seed("rls0000001", "ROLE_ADMIN", true);
        assignRole.assign(new AssignRoleCommand("use0000001", "rls0000001", "10.0.0.2"));

        revokeRole.revoke(new RevokeRoleCommand("use0000001", "rls0000001", "10.0.0.2"));

        assertTrue(assignments.findActive("use0000001", "rls0000001").isEmpty());
        assertEquals(AuditAction.DELETE, audits.logs().getLast().action());
    }

    @Test
    void revokingAnUnassignedRoleFails() {
        assertThrows(RoleNotFoundException.class,
                () -> revokeRole.revoke(new RevokeRoleCommand("use0000001", "rls0000001", null)));
    }

    @Test
    void grantsPermissionThroughTheEnabledRoleChain() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        roles.seed("rls0000001", "ROLE_ADMIN", true);
        permissions.seed("prm0000001", "METER.READ");
        assignRole.assign(new AssignRoleCommand("use0000001", "rls0000001", null));
        SystemRole role = roles.findActive("rls0000001").orElseThrow();
        grants.save(SystemRolePermission.grant(role, permissions.findActive("prm0000001").orElseThrow(), CLOCK.instant()));

        assertTrue(checkPermission.check(new CheckPermissionQuery("use0000001", "METER.READ")));
    }

    @Test
    void deniesWhenThePermissionCodeIsUnknown() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);

        assertFalse(checkPermission.check(new CheckPermissionQuery("use0000001", "METER.WRITE")));
    }

    @Test
    void deniesWhenTheUserHoldsNoRole() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        permissions.seed("prm0000001", "METER.READ");

        assertFalse(checkPermission.check(new CheckPermissionQuery("use0000001", "METER.READ")));
    }

    @Test
    void deniesWhenTheAssignedRoleIsDisabled() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        SystemRole role = roles.seed("rls0000001", "ROLE_ADMIN", true);
        permissions.seed("prm0000001", "METER.READ");
        assignRole.assign(new AssignRoleCommand("use0000001", "rls0000001", null));
        grants.save(SystemRolePermission.grant(role, permissions.findActive("prm0000001").orElseThrow(), CLOCK.instant()));
        role.disable();
        roles.save(role);

        assertFalse(checkPermission.check(new CheckPermissionQuery("use0000001", "METER.READ")));
    }

    @Test
    void deniesWhenTheAccountCannotAuthenticate() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.BLOCKED);
        roles.seed("rls0000001", "ROLE_ADMIN", true);
        permissions.seed("prm0000001", "METER.READ");

        SystemRole role = roles.findActive("rls0000001").orElseThrow();
        assignments.save(com.energymonitor.security.domain.model.UserSystemRole.assign(
                users.findActive("use0000001").orElseThrow(), role, CLOCK.instant()));
        grants.save(SystemRolePermission.grant(role, permissions.findActive("prm0000001").orElseThrow(), CLOCK.instant()));

        assertFalse(checkPermission.check(new CheckPermissionQuery("use0000001", "METER.READ")));
    }

    @Test
    void listsEveryCodeTheCallerHoldsThroughItsEnabledRoles() {
        seedUserWithRoleAndPermissions();

        assertEquals(List.of("ALERT.READ", "METER.READ"),
                checkPermission.listGrantedCodes("use0000001"));
    }

    @Test
    void listsNoCodeWhenTheUserHoldsNoRole() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        permissions.seed("prm0000001", "METER.READ");

        assertTrue(checkPermission.listGrantedCodes("use0000001").isEmpty());
    }

    @Test
    void listsNoCodeWhenTheAssignedRoleIsDisabled() {
        SystemRole role = seedUserWithRoleAndPermissions();
        role.disable();
        roles.save(role);

        assertTrue(checkPermission.listGrantedCodes("use0000001").isEmpty());
    }

    @Test
    void listsNoCodeWhenTheAccountCannotAuthenticate() {
        // Authenticated but entitled to nothing: an empty list, not a failure.
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.BLOCKED);
        SystemRole role = roles.seed("rls0000001", "ROLE_ADMIN", true);
        Permission permission = permissions.seed("prm0000001", "METER.READ");
        assignments.save(com.energymonitor.security.domain.model.UserSystemRole.assign(
                users.findActive("use0000001").orElseThrow(), role, CLOCK.instant()));
        grants.save(SystemRolePermission.grant(role, permission, CLOCK.instant()));

        assertTrue(checkPermission.listGrantedCodes("use0000001").isEmpty());
    }

    @Test
    void theListedCodesAndTheSingleCodeCheckNeverDisagree() {
        // Both answers come out of one resolution of the chain, so this holds by construction
        // rather than by luck: a code is in the list if and only if check() says yes.
        seedUserWithRoleAndPermissions();

        List<String> listed = checkPermission.listGrantedCodes("use0000001");
        for (String code : List.of("METER.READ", "ALERT.READ", "METER.WRITE", "ALERT.DELETE")) {
            assertEquals(listed.contains(code),
                    checkPermission.check(new CheckPermissionQuery("use0000001", code)),
                    "The list and the check disagree about " + code);
        }
    }

    @Test
    void listingThePermissionsOfAnUnknownAccountFails() {
        assertThrows(UserNotFoundException.class,
                () -> checkPermission.listGrantedCodes("ghost"));
    }

    /**
     * A user holding ROLE_ADMIN, which grants METER.READ and ALERT.READ.
     *
     * @return the seeded role so a test can disable it
     */
    private SystemRole seedUserWithRoleAndPermissions() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        SystemRole role = roles.seed("rls0000001", "ROLE_ADMIN", true);
        Permission meterRead = permissions.seed("prm0000001", "METER.READ");
        Permission alertRead = permissions.seed("prm0000002", "ALERT.READ");
        assignments.save(com.energymonitor.security.domain.model.UserSystemRole.assign(
                users.findActive("use0000001").orElseThrow(), role, CLOCK.instant()));
        grants.save(SystemRolePermission.grant(role, meterRead, CLOCK.instant()));
        grants.save(SystemRolePermission.grant(role, alertRead, CLOCK.instant()));
        return role;
    }
}