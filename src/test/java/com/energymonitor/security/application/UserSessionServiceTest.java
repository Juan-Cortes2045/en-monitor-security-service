package com.energymonitor.security.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.command.CreateUserSessionCommand;
import com.energymonitor.security.application.command.LogoutUserSessionCommand;
import com.energymonitor.security.application.exception.AccountNotActiveException;
import com.energymonitor.security.application.exception.SessionNotFoundException;
import com.energymonitor.security.application.usecase.CreateUserSessionService;
import com.energymonitor.security.application.usecase.LogoutUserSessionService;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.UserSession;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

/**
 * {@code CreateUserSession} and {@code LogoutUserSession} requirements: a session opens with
 * an opaque refresh token and a fixed lifetime, and revoking one is terminal and audited.
 */
class UserSessionServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-03-01T12:00:00Z"), ZoneOffset.UTC);

    private final UseCaseFixtures.FakeUserPersistencePort users = new UseCaseFixtures.FakeUserPersistencePort();
    private final UseCaseFixtures.FakeUserSessionPersistencePort sessions =
            new UseCaseFixtures.FakeUserSessionPersistencePort();
    private final UseCaseFixtures.FakeTokenGeneratorPort tokenGenerator = new UseCaseFixtures.FakeTokenGeneratorPort();
    private final UseCaseFixtures.FakeIdentifierGeneratorPort identifiers =
            new UseCaseFixtures.FakeIdentifierGeneratorPort();
    private final UseCaseFixtures.FakeAuditLogPersistencePort audits =
            new UseCaseFixtures.FakeAuditLogPersistencePort();
    private final CreateUserSessionService createSession =
            new CreateUserSessionService(users, sessions, identifiers, CLOCK);
    private final LogoutUserSessionService logoutSession =
            new LogoutUserSessionService(sessions, audits, identifiers, CLOCK);

    @Test
    void opensAnActiveSessionWithOpaqueFreshRefreshToken() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);

        UserSession session = createSession.create(
                new CreateUserSessionCommand("use0000001", "10.0.0.9", "test-agent"));

        assertTrue(session.isActive(CLOCK.instant()));
        assertEquals(CLOCK.instant().plus(Duration.ofDays(7)), session.expirationAt());
        assertEquals("10.0.0.9", session.ipAddress().orElseThrow());
    }

    @Test
    void refusesToOpenASessionForANonActiveAccount() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.BLOCKED);

        assertThrows(AccountNotActiveException.class,
                () -> createSession.create(new CreateUserSessionCommand("use0000001", null, null)));
    }

    @Test
    void logoutClosesTheSessionAndIsAudited() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        UserSession session = createSession.create(
                new CreateUserSessionCommand("use0000001", "10.0.0.9", null));

        logoutSession.logout(new LogoutUserSessionCommand(session.idUserSession(), "use0000001", "10.0.0.9"));

        UserSession closed = sessions.findActive(session.idUserSession()).orElseThrow();
        assertFalse(closed.isActive(CLOCK.instant()));
        assertEquals(CLOCK.instant(), closed.closedAt().orElseThrow());
        assertEquals(AuditAction.LOGOUT, audits.logs().getFirst().action());
    }

    @Test
    void logoutIsNotASecurityEventSoTheSessionIsNotRevoked() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        UserSession session = createSession.create(
                new CreateUserSessionCommand("use0000001", "10.0.0.9", null));

        logoutSession.logout(new LogoutUserSessionCommand(session.idUserSession(), "use0000001", "10.0.0.9"));

        // Walking away is not a compromise, so the row must stay distinguishable from one.
        UserSession closed = sessions.findActive(session.idUserSession()).orElseThrow();
        assertFalse(closed.isRevoked());
        assertTrue(closed.revokedAt().isEmpty());
        assertTrue(closed.revokedReason().isEmpty());
    }

    @Test
    void attributesTheLogoutToTheSessionOwnerAndNotTheCommand() {
        users.seed("use0000002", "per0000002", "bob@example.com", UserStatus.ACTIVE);
        UserSession session = createSession.create(
                new CreateUserSessionCommand("use0000002", "10.0.0.9", null));

        logoutSession.logout(new LogoutUserSessionCommand(session.idUserSession(), "use0000001", "10.0.0.9"));

        assertFalse(sessions.findActive(session.idUserSession()).orElseThrow().isActive(CLOCK.instant()));
        AuditLog logout = audits.logs().getFirst();
        assertEquals(AuditAction.LOGOUT, logout.action());
        assertEquals("use0000002", logout.idUser().orElseThrow());
    }

    @Test
    void cannotRevokeAnUnknownSession() {
        assertThrows(SessionNotFoundException.class,
                () -> logoutSession.logout(new LogoutUserSessionCommand("ghost", "use0000001", null)));
    }
}