package com.energymonitor.security.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.command.CreateUserSessionCommand;
import com.energymonitor.security.application.command.RefreshSessionCommand;
import com.energymonitor.security.application.port.in.CreateUserSession;
import com.energymonitor.security.application.port.in.RefreshSession;
import com.energymonitor.security.application.result.RefreshSessionResult;
import com.energymonitor.security.application.result.RefreshStatus;
import com.energymonitor.security.application.usecase.CreateUserSessionService;
import com.energymonitor.security.application.usecase.RefreshSessionService;
import com.energymonitor.security.domain.model.RefreshToken;
import com.energymonitor.security.domain.model.RefreshTokenStatus;
import com.energymonitor.security.domain.model.RevocationReason;
import com.energymonitor.security.domain.model.UserSession;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The refresh exchange: single use, lineage preserved, session identity kept, and a replay
 * escalated into a family-wide revocation.
 */
class RefreshSessionServiceTest {

    private static final Instant NOW = Instant.parse("2026-05-01T10:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private final UseCaseFixtures.FakeUserPersistencePort users =
            new UseCaseFixtures.FakeUserPersistencePort();
    private final UseCaseFixtures.FakeUserSessionPersistencePort sessions =
            new UseCaseFixtures.FakeUserSessionPersistencePort();
    private final UseCaseFixtures.FakeTokenGeneratorPort secrets =
            new UseCaseFixtures.FakeTokenGeneratorPort();
    private final UseCaseFixtures.FakeIdentifierGeneratorPort identifiers =
            new UseCaseFixtures.FakeIdentifierGeneratorPort();
    private final UseCaseFixtures.FakeAuditLogPersistencePort audits =
            new UseCaseFixtures.FakeAuditLogPersistencePort();
    private final RefreshTokenFixtures.FakeRefreshTokenPersistencePort tokens =
            new RefreshTokenFixtures.FakeRefreshTokenPersistencePort();
    private final RefreshTokenFixtures.FakeRefreshTokenHasher hasher =
            new RefreshTokenFixtures.FakeRefreshTokenHasher();

    private CreateUserSession createSession;
    private RefreshSession refresh;

    @BeforeEach
    void setUp() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        createSession = new CreateUserSessionService(users, sessions, identifiers, CLOCK);
        refresh = new RefreshSessionService(tokens, sessions, users, hasher, secrets, audits,
                identifiers, CLOCK);
    }

    private UserSession openSession() {
        return createSession.create(new CreateUserSessionCommand("use0000001", "10.0.0.9", null));
    }

    /**
     * Opens a session and issues its root generation.
     *
     * <p>The root secret is deliberately not named like the ones {@code FakeTokenGeneratorPort}
     * hands out. A collision would overwrite the row in the fake's hash index, which is
     * exactly the kind of accident this fixture must not create.
     */
    private UserSession issueRoot(String rootSecret) {
        UserSession session = openSession();
        tokens.save(RefreshToken.root("rft0000001", session.idUserSession(),
                hasher.hash(rootSecret), NOW, NOW.plusSeconds(604800)));
        return session;
    }

    @Test
    void rotatesAnActiveTokenAndIssuesItsSuccessor() {
        String first = "raiz-1";
        issueRoot(first);

        RefreshSessionResult result =
                refresh.refresh(new RefreshSessionCommand(first, "10.0.0.9"));

        assertEquals(RefreshStatus.ROTATED, result.status());
        assertNotEquals(first, result.rawRefreshToken());
        assertTrue(result.issued());
    }

    @Test
    void retiresThePresentedGeneration() {
        String first = "raiz-1";
        issueRoot(first);

        refresh.refresh(new RefreshSessionCommand(first, "10.0.0.9"));

        RefreshToken presented = tokens.findByTokenHash(hasher.hash(first)).orElseThrow();
        assertEquals(RefreshTokenStatus.ROTATED, presented.status());
        assertTrue(presented.rotatedAt().isPresent());
    }

    @Test
    void theSuccessorIsActiveAndPointsAtItsPredecessor() {
        String first = "raiz-1";
        issueRoot(first);

        RefreshSessionResult result = refresh.refresh(new RefreshSessionCommand(first, null));

        RefreshToken successor = tokens.findByTokenHash(
                hasher.hash(result.rawRefreshToken())).orElseThrow();
        assertEquals(RefreshTokenStatus.ACTIVE, successor.status());
        assertEquals("rft0000001", successor.parentId().orElseThrow());
    }

    @Test
    void keepsTheWholeChainInOneFamilyAcrossThreeGenerations() {
        String first = "raiz-1";
        UserSession session = issueRoot(first);
        String second = refresh.refresh(new RefreshSessionCommand(first, null)).rawRefreshToken();
        String third = refresh.refresh(new RefreshSessionCommand(second, null)).rawRefreshToken();

        RefreshToken one = tokens.findByTokenHash(hasher.hash(first)).orElseThrow();
        RefreshToken two = tokens.findByTokenHash(hasher.hash(second)).orElseThrow();
        RefreshToken three = tokens.findByTokenHash(hasher.hash(third)).orElseThrow();

        // Three distinct generations, one family.
        assertEquals(3, tokens.size());
        assertEquals(one.familyId(), two.familyId());
        assertEquals(two.familyId(), three.familyId());
        assertTrue(one.isRoot());
        assertEquals(one.idRefreshToken(), two.parentId().orElseThrow());
        assertEquals(two.idRefreshToken(), three.parentId().orElseThrow());
    }

    @Test
    void rotationKeepsTheSameSessionRatherThanOpeningANewOne() {
        String first = "raiz-1";
        UserSession session = issueRoot(first);
        String sessionId = session.idUserSession();
        int sessionsBefore = sessions.listActiveByUser("use0000001").size();

        RefreshSessionResult result = refresh.refresh(new RefreshSessionCommand(first, null));

        assertEquals(sessionId, result.idUserSession());
        assertEquals(sessionsBefore, sessions.listActiveByUser("use0000001").size(),
                "Rotating a secret must not mint a second login");
    }

    @Test
    void theSuccessorBelongsToTheSessionItWasRotatedAgainst() {
        String first = "raiz-1";
        UserSession session = issueRoot(first);
        String sessionId = session.idUserSession();

        String second = refresh.refresh(new RefreshSessionCommand(first, null)).rawRefreshToken();

        assertEquals(sessionId, tokens.findByTokenHash(hasher.hash(second)).orElseThrow()
                .idUserSession());
    }

    @Test
    void rejectsAnUnknownTokenWithoutIssuingAnything() {
        RefreshSessionResult result =
                refresh.refresh(new RefreshSessionCommand("nunca-emitido", null));

        assertEquals(RefreshStatus.REJECTED, result.status());
        assertNull(result.rawRefreshToken());
        assertEquals(0, tokens.size());
    }

    @Test
    void detectsReuseOfARetiredTokenAndRevokesTheFamily() {
        String first = "raiz-1";
        UserSession session = issueRoot(first);
        String second = refresh.refresh(new RefreshSessionCommand(first, null)).rawRefreshToken();

        RefreshSessionResult result = refresh.refresh(new RefreshSessionCommand(first, null));

        assertEquals(RefreshStatus.REUSE_DETECTED, result.status());
        assertNull(result.rawRefreshToken(), "A replay must never hand out a new credential");
        assertEquals(0, tokens.countWithStatus(RefreshTokenStatus.ACTIVE),
                "No generation of a compromised family may stay active");
    }

    @Test
    void aReplayRevokesTheSessionAsCompromised() {
        String first = "raiz-1";
        UserSession session = issueRoot(first);
        refresh.refresh(new RefreshSessionCommand(first, null));

        refresh.refresh(new RefreshSessionCommand(first, null));

        UserSession read = sessions.findActive(session.idUserSession()).orElseThrow();
        assertTrue(read.isRevoked());
        assertEquals(RevocationReason.REFRESH_TOKEN_REUSE, read.revokedReason().orElseThrow());
        assertFalse(session.closedAt().isPresent(), "A compromise is not an ordinary logout");
    }

    @Test
    void aReplayKeepsTheRetiredGenerationRetiredRatherThanDowngradingIt() {
        String first = "raiz-1";
        UserSession session = issueRoot(first);
        refresh.refresh(new RefreshSessionCommand(first, null));

        refresh.refresh(new RefreshSessionCommand(first, null));

        // The spent token stays identifiable as spent; that is what made the replay visible.
        assertEquals(RefreshTokenStatus.ROTATED,
                tokens.findByTokenHash(hasher.hash(first)).orElseThrow().status());
    }

    @Test
    void afterAReplayTheCurrentGenerationIsAlsoRefused() {
        String first = "raiz-1";
        UserSession session = issueRoot(first);
        String second = refresh.refresh(new RefreshSessionCommand(first, null)).rawRefreshToken();
        refresh.refresh(new RefreshSessionCommand(first, null));

        RefreshSessionResult result = refresh.refresh(new RefreshSessionCommand(second, null));

        assertEquals(RefreshStatus.REJECTED, result.status());
        assertNull(result.rawRefreshToken());
    }

    @Test
    void aRevokedTokenIsRefusedWithoutBeingTreatedAsAReplay() {
        String first = "raiz-1";
        UserSession session = issueRoot(first);
        session.revoke(NOW, RevocationReason.PASSWORD_CHANGED);
        sessions.save(session);

        RefreshSessionResult result = refresh.refresh(new RefreshSessionCommand(first, null));

        assertEquals(RefreshStatus.REJECTED, result.status());
    }

    @Test
    void refusesToRotateOnceTheSessionIsClosed() {
        String first = "raiz-1";
        UserSession session = issueRoot(first);
        session.close(NOW);
        sessions.save(session);

        RefreshSessionResult result = refresh.refresh(new RefreshSessionCommand(first, null));

        assertEquals(RefreshStatus.REJECTED, result.status());
        assertEquals(1, tokens.size(), "Nothing may be minted for a closed session");
    }

    /** A root whose window closed before the pinned clock the service runs on. */
    private String issueAgedRoot() {
        UserSession session = openSession();
        tokens.save(RefreshToken.root("rft0000001", session.idUserSession(),
                hasher.hash("raiz-vencida"),
                NOW.minus(Duration.ofDays(30)), NOW.minus(Duration.ofDays(23))));
        return "raiz-vencida";
    }

    @Test
    void anExpiredTokenIsRejectedWithoutIssuingAnything() {
        String aged = issueAgedRoot();

        RefreshSessionResult result = refresh.refresh(new RefreshSessionCommand(aged, null));

        assertEquals(RefreshStatus.REJECTED, result.status());
        assertNull(result.rawRefreshToken());
        assertNull(result.identity());
        assertEquals(1, tokens.size(), "An expired token must not produce a successor");
    }

    @Test
    void anExpiredTokenDoesNotRevokeTheSession() {
        String aged = issueAgedRoot();

        refresh.refresh(new RefreshSessionCommand(aged, null));

        UserSession session = sessions.findActive("id0000001").orElseThrow();
        assertFalse(session.isRevoked(), "A slow client is not a compromised one");
        assertTrue(session.closedAt().isEmpty());
        assertTrue(session.isActive(NOW), "The session is untouched by an expired token");
    }

    @Test
    void anExpiredTokenDoesNotRevokeItsFamily() {
        String aged = issueAgedRoot();

        refresh.refresh(new RefreshSessionCommand(aged, null));

        assertEquals(1, tokens.size());
        assertEquals(RefreshTokenStatus.ACTIVE, tokens.findByTokenHash(hasher.hash(aged))
                .orElseThrow().status(), "Expiry leaves the stored state alone");
    }

    @Test
    void anExpiredTokenIsNotEscalatedToAReuseIncident() {
        String aged = issueAgedRoot();

        RefreshSessionResult result = refresh.refresh(new RefreshSessionCommand(aged, null));

        // Escalating would revoke the family and the session over a lagging clock.
        assertEquals(RefreshStatus.REJECTED, result.status());
        assertEquals(0, audits.logs().size(), "A plain expiry is not an audit-worthy event");
    }

    @Test
    void aFamilyGrowsWithoutAnyCapBecauseNoPolicyIsDefined() {
        // Recorded as a technical debt, not endorsed. Nothing in the project states how many
        // generations a family may have, so no limit is imposed here; a future policy has to
        // decide both the number and where it is enforced.
        issueRoot("raiz-1");
        String current = "raiz-1";

        for (int generation = 2; generation <= 8; generation++) {
            current = refresh.refresh(new RefreshSessionCommand(current, null)).rawRefreshToken();
        }

        assertEquals(8, tokens.size(), "Generations accumulate with no ceiling");
        assertEquals(1, tokens.listByFamily("rft0000001").stream()
                .filter(token -> token.status() == RefreshTokenStatus.ACTIVE).count(),
                "Only the newest generation stays active");
        assertEquals("rft0000001", tokens.findByTokenHash(hasher.hash("raiz-1")).orElseThrow()
                .familyId(), "Every generation still shares the original family");
    }

    @Test
    void auditsTheRotation() {
        String first = "raiz-1";
        UserSession session = issueRoot(first);

        refresh.refresh(new RefreshSessionCommand(first, "203.0.113.5"));

        assertEquals(1, audits.logs().size());
        assertEquals("203.0.113.5", audits.logs().getFirst().ipAddress().orElseThrow());
    }

    @Test
    void auditsTheReplay() {
        String first = "raiz-1";
        UserSession session = issueRoot(first);
        refresh.refresh(new RefreshSessionCommand(first, null));

        refresh.refresh(new RefreshSessionCommand(first, "198.51.100.7"));

        List<String> descriptions = audits.logs().stream()
                .map(log -> log.description().orElse(""))
                .toList();
        assertTrue(descriptions.stream().anyMatch(text -> text.contains("reuse")));
    }
}
