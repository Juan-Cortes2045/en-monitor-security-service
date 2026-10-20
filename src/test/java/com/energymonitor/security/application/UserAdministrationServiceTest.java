package com.energymonitor.security.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.api.AccountAdministered;
import com.energymonitor.security.application.command.AdministerAccountRoleCommand;
import com.energymonitor.security.application.command.AdministerAccountStatusCommand;
import com.energymonitor.security.application.command.ListUserAccountsQuery;
import com.energymonitor.security.application.exception.RoleNotFoundException;
import com.energymonitor.security.application.exception.SelfAdministrationException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.out.UserDirectoryPort;
import com.energymonitor.security.application.result.UserAccountPage;
import com.energymonitor.security.application.usecase.AdministerUserAccountService;
import com.energymonitor.security.application.usecase.AssignRoleService;
import com.energymonitor.security.application.usecase.ListUserAccountsService;
import com.energymonitor.security.application.usecase.ManageUserStatusService;
import com.energymonitor.security.application.usecase.RevokeRoleService;
import com.energymonitor.security.domain.model.RevocationReason;
import com.energymonitor.security.domain.model.UserSession;
import com.energymonitor.security.domain.model.UserStatus;
import com.energymonitor.security.domain.model.UserSystemRole;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Administration of other accounts: the directory lists global roles, an administrator never
 * acts on their own account, and an account that stops being active loses its sessions.
 */
class UserAdministrationServiceTest {

    private static final Instant NOW = Instant.parse("2026-03-01T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String ADMIN = "adm0000001";
    private static final String TARGET = "use0000002";

    private final UseCaseFixtures.FakeUserPersistencePort users = new UseCaseFixtures.FakeUserPersistencePort();
    private final UseCaseFixtures.FakeSystemRolePersistencePort roles =
            new UseCaseFixtures.FakeSystemRolePersistencePort();
    private final UseCaseFixtures.FakeUserSystemRolePersistencePort assignments =
            new UseCaseFixtures.FakeUserSystemRolePersistencePort();
    private final UseCaseFixtures.FakeUserSessionPersistencePort sessions =
            new UseCaseFixtures.FakeUserSessionPersistencePort();
    private final UseCaseFixtures.FakeAuditLogPersistencePort audits =
            new UseCaseFixtures.FakeAuditLogPersistencePort();
    private final UseCaseFixtures.FakeIdentifierGeneratorPort identifiers =
            new UseCaseFixtures.FakeIdentifierGeneratorPort();

    private final UseCaseFixtures.FakeAccountEventPublisherPort events =
            new UseCaseFixtures.FakeAccountEventPublisherPort();

    private final AdministerUserAccountService administer = new AdministerUserAccountService(
            users, roles, assignments, sessions,
            new ManageUserStatusService(users, audits, identifiers, CLOCK),
            new AssignRoleService(users, roles, assignments, audits, identifiers, CLOCK),
            new RevokeRoleService(assignments, audits, identifiers, CLOCK), events, CLOCK);

    UserAdministrationServiceTest() {
        users.seed(ADMIN, "per0000001", "admin@example.com", UserStatus.ACTIVE);
        users.seed(TARGET, "per0000002", "ada@example.com", UserStatus.ACTIVE);
        roles.seed("rol0000001", "ADMIN", true);
        assignments.save(new UserSystemRole(ADMIN, "rol0000001", NOW));
    }

    private static AdministerAccountRoleCommand role(String actor, String target, String name) {
        return new AdministerAccountRoleCommand(actor, target, name, "10.0.0.1");
    }

    private static AdministerAccountStatusCommand status(String actor, String target, UserStatus to) {
        return new AdministerAccountStatusCommand(actor, target, to, "10.0.0.1");
    }

    // ------------------------------------------------------------------ directory

    @Test
    void listsTheDirectoryWithTheGlobalRolesOfEachAccount() {
        UserDirectoryPort directory = (text, page, size) -> new UserDirectoryPort.Page(List.of(
                new UserDirectoryPort.Entry(ADMIN, "admin@example.com", "Grace", "Hopper",
                        UserStatus.ACTIVE, true, NOW, NOW),
                new UserDirectoryPort.Entry(TARGET, "ada@example.com", "Ada", null,
                        UserStatus.BLOCKED, false, NOW, null)), 7);
        ListUserAccountsService list = new ListUserAccountsService(directory, assignments, roles);

        UserAccountPage page = list.list(new ListUserAccountsQuery(" ada ", 0, 2));

        assertEquals(7, page.totalItems());
        assertEquals(List.of("ADMIN"), page.items().get(0).roles());
        assertEquals(List.of(), page.items().get(1).roles());
        assertEquals(UserStatus.BLOCKED, page.items().get(1).status());
    }

    @Test
    void passesTheTrimmedSearchAndThePageToTheDirectory() {
        String[] seen = new String[1];
        UserDirectoryPort directory = (text, page, size) -> {
            seen[0] = text + "|" + page + "|" + size;
            return new UserDirectoryPort.Page(List.of(), 0);
        };

        new ListUserAccountsService(directory, assignments, roles)
                .list(new ListUserAccountsQuery("  ada ", 3, 10));

        assertEquals("ada|3|10", seen[0]);
    }

    @Test
    void refusesAPageSizeOutOfRange() {
        assertThrows(IllegalArgumentException.class, () -> new ListUserAccountsQuery(null, 0, 0));
        assertThrows(IllegalArgumentException.class, () -> new ListUserAccountsQuery(null, 0, 51));
        assertThrows(IllegalArgumentException.class, () -> new ListUserAccountsQuery(null, -1, 10));
    }

    @Test
    void listsOnlyAssignableRoles() {
        roles.seed("rol0000002", "AUDITOR", false);
        ListUserAccountsService list = new ListUserAccountsService(
                (text, page, size) -> new UserDirectoryPort.Page(List.of(), 0), assignments, roles);

        assertEquals(List.of("ADMIN"),
                list.listAssignableRoles().stream().map(r -> r.name()).toList());
    }

    // ---------------------------------------------------------------------- status

    @Test
    void blockingAnAccountRevokesItsOpenSessions() {
        sessions.save(UserSession.open("ses0000001", TARGET, NOW.minusSeconds(60),
                NOW.plusSeconds(3600), null, null));

        administer.changeStatus(status(ADMIN, TARGET, UserStatus.BLOCKED));

        assertEquals(UserStatus.BLOCKED, users.findActive(TARGET).orElseThrow().status());
        UserSession session = sessions.findActive("ses0000001").orElseThrow();
        assertTrue(session.isRevoked());
        assertEquals(RevocationReason.ADMINISTRATIVE, session.revokedReason().orElseThrow());
        assertEquals(1, audits.logs().size());
    }

    @Test
    void announcesAStatusChangeOnlyWhenTheStatusReallyChanges() {
        administer.changeStatus(status(ADMIN, TARGET, UserStatus.BLOCKED));
        administer.changeStatus(status(ADMIN, TARGET, UserStatus.BLOCKED));

        assertEquals(List.of(new AccountAdministered(ADMIN, TARGET,
                        AccountAdministered.Action.STATUS_CHANGED, "BLOCKED", NOW)),
                events.eventsOf(AccountAdministered.class));
    }

    @Test
    void announcesAGrantAndARevocationButNotTheirRepetitions() {
        administer.grantRole(role(ADMIN, TARGET, "ADMIN"));
        administer.grantRole(role(ADMIN, TARGET, "ADMIN"));
        administer.revokeRole(role(ADMIN, TARGET, "ADMIN"));
        administer.revokeRole(role(ADMIN, TARGET, "ADMIN"));

        assertEquals(List.of(AccountAdministered.Action.ROLE_GRANTED,
                        AccountAdministered.Action.ROLE_REVOKED),
                events.eventsOf(AccountAdministered.class).stream()
                        .map(AccountAdministered::action).toList());
    }

    @Test
    void announcesNothingWhenTheChangeIsRefused() {
        assertThrows(SelfAdministrationException.class,
                () -> administer.changeStatus(status(ADMIN, ADMIN, UserStatus.BLOCKED)));

        assertTrue(events.events().isEmpty());
    }

    @Test
    void reactivatingAnAccountLeavesItsSessionsAlone() {
        users.findActive(TARGET).orElseThrow().block();
        sessions.save(UserSession.open("ses0000001", TARGET, NOW.minusSeconds(60),
                NOW.plusSeconds(3600), null, null));

        administer.changeStatus(status(ADMIN, TARGET, UserStatus.ACTIVE));

        assertEquals(UserStatus.ACTIVE, users.findActive(TARGET).orElseThrow().status());
        assertFalse(sessions.findActive("ses0000001").orElseThrow().isRevoked());
    }

    @Test
    void anAdministratorCannotChangeTheirOwnStatus() {
        assertThrows(SelfAdministrationException.class,
                () -> administer.changeStatus(status(ADMIN, ADMIN, UserStatus.BLOCKED)));

        assertEquals(UserStatus.ACTIVE, users.findActive(ADMIN).orElseThrow().status());
        assertTrue(audits.logs().isEmpty());
    }

    @Test
    void changingTheStatusOfAMissingAccountIsNotFound() {
        assertThrows(UserNotFoundException.class,
                () -> administer.changeStatus(status(ADMIN, "nob0000001", UserStatus.BLOCKED)));
    }

    // ----------------------------------------------------------------------- roles

    @Test
    void grantsAGlobalRoleByName() {
        administer.grantRole(role(ADMIN, TARGET, "ADMIN"));

        assertTrue(assignments.findActive(TARGET, "rol0000001").isPresent());
    }

    @Test
    void grantingARoleAlreadyHeldChangesNothing() {
        administer.grantRole(role(ADMIN, TARGET, "ADMIN"));
        administer.grantRole(role(ADMIN, TARGET, "ADMIN"));

        assertEquals(1, assignments.listActiveByUser(TARGET).size());
        assertEquals(1, audits.logs().size());
    }

    @Test
    void revokesAGlobalRoleByName() {
        administer.grantRole(role(ADMIN, TARGET, "ADMIN"));

        administer.revokeRole(role(ADMIN, TARGET, "ADMIN"));

        assertTrue(assignments.findActive(TARGET, "rol0000001").isEmpty());
    }

    @Test
    void revokingARoleNotHeldChangesNothing() {
        administer.revokeRole(role(ADMIN, TARGET, "ADMIN"));

        assertTrue(audits.logs().isEmpty());
    }

    @Test
    void anAdministratorCannotRevokeTheirOwnRole() {
        assertThrows(SelfAdministrationException.class,
                () -> administer.revokeRole(role(ADMIN, ADMIN, "ADMIN")));

        assertTrue(assignments.findActive(ADMIN, "rol0000001").isPresent());
    }

    @Test
    void anUnknownOrDisabledRoleIsNotFound() {
        roles.seed("rol0000002", "AUDITOR", false);

        assertThrows(RoleNotFoundException.class,
                () -> administer.grantRole(role(ADMIN, TARGET, "SUPERUSER")));
        assertThrows(RoleNotFoundException.class,
                () -> administer.grantRole(role(ADMIN, TARGET, "AUDITOR")));
    }

    @Test
    void grantingARoleToAMissingAccountIsNotFound() {
        assertThrows(UserNotFoundException.class,
                () -> administer.grantRole(role(ADMIN, "nob0000001", "ADMIN")));
    }
}
