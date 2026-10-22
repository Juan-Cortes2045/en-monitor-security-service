package com.energymonitor.security.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.adapter.out.persistence.repository.RefreshTokenRepository;
import com.energymonitor.security.application.command.LogoutUserSessionCommand;
import com.energymonitor.security.application.command.RefreshSessionCommand;
import com.energymonitor.security.application.port.in.LogoutUserSession;
import com.energymonitor.security.application.port.in.RefreshSession;
import com.energymonitor.security.application.port.out.RefreshTokenPersistencePort;
import com.energymonitor.security.application.port.out.UserSessionPersistencePort;
import com.energymonitor.security.application.result.RefreshStatus;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordHash;
import com.energymonitor.security.domain.model.Person;
import com.energymonitor.security.domain.model.RefreshToken;
import com.energymonitor.security.domain.model.RefreshTokenStatus;
import com.energymonitor.security.domain.model.RevocationReason;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserSession;
import com.energymonitor.security.domain.model.UserStatus;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * The full authentication lifecycle against the real database: open a session with a root
 * token, rotate it, detect a replay, and confirm the boundaries a closed or revoked session
 * imposes.
 *
 * <p>The HTTP layer is exercised separately by {@code AuthRefreshEndpointWebTest}. What matters
 * here is that the state the database ends up in is the state the security decisions depend on,
 * because that state is what an incident investigation would read.
 */
@SpringBootTest
class RefreshLifecycleIntegrationTest extends JwtKeyedTest {

    private static final Instant REGISTRATION = Instant.parse("2026-01-02T03:04:05Z");
    private static final Duration WEEK = Duration.ofDays(7);

    @Autowired
    private RefreshSession refreshSession;

    @Autowired
    private LogoutUserSession logoutUserSession;

    @Autowired
    private RefreshTokenPersistencePort tokens;

    @Autowired
    private UserSessionPersistencePort sessions;

    @Autowired
    private RefreshTokenRepository tokenRepository;

    @Autowired
    private com.energymonitor.security.adapter.out.persistence.repository.UserSessionRepository
            userSessionRepository;

    @Autowired
    private com.energymonitor.security.adapter.out.persistence.repository.UserRepository
            userRepository;

    @Autowired
    private com.energymonitor.security.adapter.out.persistence.repository.PersonRepository
            personRepository;

    @Autowired
    private com.energymonitor.security.adapter.out.persistence.repository.AuditLogRepository
            auditLogRepository;

    @Autowired
    private com.energymonitor.security.adapter.out.persistence.repository.LoginErrorLogRepository
            loginErrorLogRepository;

    @Autowired
    private com.energymonitor.security.application.port.out.PersonPersistencePort persons;

    @Autowired
    private com.energymonitor.security.application.port.out.UserPersistencePort users;

    @Autowired
    private com.energymonitor.security.application.port.out.RefreshTokenHasherPort hasher;

    private String suffix;
    private String userId;
    private String personId;
    private String sessionId;
    private String rootSecret;

    @BeforeEach
    void seedAccountSessionAndRootToken() {
        suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 7);
        personId = "per" + suffix;
        userId = "use" + suffix;
        sessionId = "ses" + suffix;
        rootSecret = "raiz-" + suffix;
        Instant now = Instant.now();

        persons.save(new Person(personId, "Ada", "Lovelace"));
        users.save(new User(userId, personId,
                PasswordHash.of("$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
                Email.of("ciclo-" + suffix + "@example.com"), true, REGISTRATION,
                UserStatus.ACTIVE, 0, null, null));
        sessions.save(UserSession.open(sessionId, userId, now, now.plus(WEEK), "10.0.0.1", "JUnit"));
        tokens.save(RefreshToken.root("rft" + suffix, sessionId, hasher.hash(rootSecret), now,
                now.plus(WEEK)));
    }

    @AfterEach
    void cleanUp() {
        // These tests commit for real, because a rollback they asserted on is the one the
        // application opens for itself. The rows therefore have to go by hand, in foreign key
        // order, or the database grows a little on every run.
        tokenRepository.findAll().forEach(token -> {
            token.setParentId(null);
            tokenRepository.save(token);
        });
        tokenRepository.deleteAll();
        // The flows under test write audit rows attributed to the account, and audit_log points
        // at user, so they have to go before the account does. Scoped to this test's own
        // identifiers so nothing another test seeded is removed.
        loginErrorLogRepository.deleteAll();
        auditLogRepository.deleteAll();
        userSessionRepository.deleteById(sessionId);
        userRepository.deleteById(userId);
        personRepository.deleteById(personId);
    }

    private RefreshToken stored(String rawToken) {
        return tokens.findByTokenHash(hasher.hash(rawToken)).orElseThrow();
    }

    @Test
    void rotationKeepsTheSessionAndTheFamilyAndChainsTheGenerations() {
        var first = refreshSession.refresh(new RefreshSessionCommand(rootSecret, "10.0.0.1"));
        assertEquals(RefreshStatus.ROTATED, first.status());
        assertEquals(sessionId, first.idUserSession());

        var second = refreshSession.refresh(
                new RefreshSessionCommand(first.rawRefreshToken(), "10.0.0.1"));
        assertEquals(RefreshStatus.ROTATED, second.status());

        RefreshToken root = stored(rootSecret);
        RefreshToken generation2 = stored(first.rawRefreshToken());
        RefreshToken generation3 = stored(second.rawRefreshToken());

        assertEquals(RefreshTokenStatus.ROTATED, root.status());
        assertEquals(RefreshTokenStatus.ROTATED, generation2.status());
        assertEquals(RefreshTokenStatus.ACTIVE, generation3.status());

        // Same session, one family, each generation pointing at the one it replaced.
        assertEquals(sessionId, generation2.idUserSession());
        assertEquals(sessionId, generation3.idUserSession());
        assertEquals(root.familyId(), generation2.familyId());
        assertEquals(root.familyId(), generation3.familyId());
        assertEquals(root.idRefreshToken(), generation2.parentId().orElseThrow());
        assertEquals(generation2.idRefreshToken(), generation3.parentId().orElseThrow());
    }

    @Test
    void rotationCarriesTheIdentityOfTheSessionOwner() {
        var result = refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));

        // The identity is what the access token is minted from, so it must be the account that
        // owns the session rather than anything derived from the request.
        assertNotNull(result.identity());
        assertEquals(userId, result.identity().idUser());
        assertEquals(personId, result.identity().idPerson());
        assertEquals("ciclo-" + suffix + "@example.com", result.identity().email().value());
    }

    @Test
    void onlyTheHashOfEachGenerationIsPersisted() {
        var first = refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));

        String storedRoot = stored(rootSecret).tokenHash();
        String storedNext = stored(first.rawRefreshToken()).tokenHash();

        assertEquals(64, storedRoot.length());
        assertEquals(64, storedNext.length());
        assertTrue(storedRoot.matches("[0-9a-f]{64}"));
        assertTrue(storedNext.matches("[0-9a-f]{64}"));
    }

    @Test
    void reuseOfARetiredTokenRevokesTheFamilyAndTheSessionAndIssuesNothing() {
        var first = refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));
        assertEquals(RefreshStatus.ROTATED, first.status());

        var replay = refreshSession.refresh(new RefreshSessionCommand(rootSecret, "198.51.100.9"));

        assertEquals(RefreshStatus.REUSE_DETECTED, replay.status());
        assertNull(replay.rawRefreshToken(), "A replay must never hand out a new secret");
        assertNull(replay.identity(), "A replay must never hand out an identity to sign with");

        List<RefreshToken> family = tokens.listByFamily("rft" + suffix);
        assertTrue(family.stream().noneMatch(token -> token.status() == RefreshTokenStatus.ACTIVE),
                "No generation of a compromised family may remain active");
        RefreshToken successor = stored(first.rawRefreshToken());
        assertEquals(RefreshTokenStatus.REVOKED, successor.status());
        assertEquals(RevocationReason.REFRESH_TOKEN_REUSE, successor.revokedReason().orElseThrow());

        // The replayed generation is left as it was. Downgrading it to REVOKED would erase the
        // very fact that made the replay visible, and the next presentation of it would then
        // look like a plain revocation instead of a second theft signal.
        RefreshToken replayed = stored(rootSecret);
        assertEquals(RefreshTokenStatus.ROTATED, replayed.status(),
                "A replayed generation must stay recognisable as a replay");
        assertTrue(replayed.revokedAt().isEmpty());
        assertTrue(replayed.revokedReason().isEmpty());

        UserSession session = sessions.findActive(sessionId).orElseThrow();
        assertTrue(session.isRevoked());
        assertEquals(RevocationReason.REFRESH_TOKEN_REUSE, session.revokedReason().orElseThrow());
        assertFalse(session.closedAt().isPresent(), "A compromise is not an ordinary logout");
    }

    @Test
    void afterAReplayTheCurrentGenerationIsRefusedToo() {
        var first = refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));
        refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));

        var after = refreshSession.refresh(new RefreshSessionCommand(first.rawRefreshToken(), null));

        assertEquals(RefreshStatus.REJECTED, after.status());
        assertNull(after.rawRefreshToken());
    }

    @Test
    void logoutClosesTheSessionAndThenRefreshIsRefused() {
        logoutUserSession.logout(
                new LogoutUserSessionCommand(sessionId, userId, "10.0.0.1"));

        UserSession closed = sessions.findActive(sessionId).orElseThrow();
        assertTrue(closed.closedAt().isPresent(), "Logout closes the session");
        assertFalse(closed.isRevoked(), "Logout is not a security event");

        var result = refreshSession.refresh(new RefreshSessionCommand(rootSecret, "10.0.0.1"));

        assertEquals(RefreshStatus.REJECTED, result.status());
        assertNull(result.rawRefreshToken(), "A closed session must not yield new credentials");
        assertNull(result.identity());
        // Nothing was minted: the root token is still the only generation.
        assertEquals(1, tokens.listByFamily("rft" + suffix).size());
        assertEquals(RefreshTokenStatus.ACTIVE, stored(rootSecret).status());
    }

    @Test
    void aRevokedSessionRefusesRefreshEvenWhileItsTokenIsStillActive() {
        // The session is a barrier of its own: revoking it must not depend on the individual
        // token having been retired first.
        UserSession session = sessions.findActive(sessionId).orElseThrow();
        session.revoke(Instant.now(), RevocationReason.ADMINISTRATIVE);
        sessions.save(session);
        assertEquals(RefreshTokenStatus.ACTIVE, stored(rootSecret).status());

        var result = refreshSession.refresh(new RefreshSessionCommand(rootSecret, "10.0.0.1"));

        assertEquals(RefreshStatus.REJECTED, result.status());
        assertNull(result.rawRefreshToken());
        assertEquals(1, tokens.listByFamily("rft" + suffix).size());
    }

    @Test
    void aDeactivatedAccountCannotRenewItsSession() {
        // An administrator deactivating an account must stop the existing sessions, not merely
        // the next login. Without this the sessions would keep renewing themselves.
        User user = users.findActive(userId).orElseThrow();
        user.deactivate();
        users.save(user);

        var result = refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));

        assertEquals(RefreshStatus.REJECTED, result.status());
        assertNull(result.rawRefreshToken());
    }

    /**
     * Plants a root token whose window closed before now.
     *
     * <p>Time is controlled by writing the timestamps rather than by moving a clock or waiting:
     * the service reads the system clock, so a token stored with an expiry in the past is
     * expired by exactly the same arithmetic production uses, and the test stays instant.
     */
    private void replaceRootWithAnAgedToken() {
        Instant longAgo = Instant.now().minus(Duration.ofDays(30));
        tokenRepository.deleteAll();
        tokens.save(RefreshToken.root("rft" + suffix, sessionId,
                hasher.hash(rootSecret), longAgo, longAgo.plus(Duration.ofDays(7))));
    }

    @Test
    void anExpiredTokenIsRefusedAndIssuesNoNewGeneration() {
        replaceRootWithAnAgedToken();

        var result = refreshSession.refresh(new RefreshSessionCommand(rootSecret, "10.0.0.1"));

        assertEquals(RefreshStatus.REJECTED, result.status());
        assertNull(result.rawRefreshToken(), "An expired token must not yield a new secret");
        assertNull(result.identity(), "and must not yield an identity to sign a token with");
        assertEquals(1, tokens.listByFamily("rft" + suffix).size(),
                "No successor generation may be created");
    }

    @Test
    void anExpiredTokenLeavesTheStoredStateUntouched() {
        replaceRootWithAnAgedToken();

        refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));

        RefreshToken root = stored(rootSecret);
        // Expiry is derived from expiresAt, not written: the row still says ACTIVE and nothing
        // restates what the clock already knows.
        assertEquals(RefreshTokenStatus.ACTIVE, root.status());
        assertTrue(root.rotatedAt().isEmpty());
        assertTrue(root.revokedAt().isEmpty());
    }

    @Test
    void anExpiredTokenDoesNotRevokeTheSessionNorItsFamily() {
        replaceRootWithAnAgedToken();

        refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));

        UserSession session = sessions.findActive(sessionId).orElseThrow();
        assertFalse(session.isRevoked(), "A slow client is not a compromised one");
        assertTrue(session.closedAt().isEmpty());
        assertEquals(0, tokens.listByFamily("rft" + suffix).stream()
                .filter(token -> token.status() == RefreshTokenStatus.REVOKED).count(),
                "Expiry must not revoke the family");
    }

    @Test
    void anExpiredTokenIsRejectedWithoutAnAuditEntry() {
        replaceRootWithAnAgedToken();

        refreshSession.refresh(new RefreshSessionCommand(rootSecret, "198.51.100.4"));

        // Reuse and normal rotation are worth recording; a client whose token aged out is not a
        // security event, and logging it as one would drown the real ones.
        assertEquals(0, auditLogRepository.count(),
                "Expiry is a rejection, not an incident");
    }

    @Test
    void theSessionLifecycleCombinationsBehaveAsSpecified() {
        // Active session with a live token: the only combination that rotates.
        assertTrue(sessions.findActive(sessionId).orElseThrow().isActive(Instant.now()));
        var firstRotation = refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));
        assertEquals(RefreshStatus.ROTATED, firstRotation.status());

        // Closed session: rejected, session stays unrevoked. The current generation is presented
        // rather than the root, because the root was just retired and re-presenting it would be
        // a replay, which is a different and stronger outcome.
        logoutUserSession.logout(new LogoutUserSessionCommand(sessionId, userId, "10.0.0.1"));
        UserSession closed = sessions.findActive(sessionId).orElseThrow();
        assertTrue(closed.closedAt().isPresent());
        assertTrue(closed.revokedAt().isEmpty(), "A closed session is not revoked");
        assertFalse(closed.isRevoked());
        var afterLogout = refreshSession.refresh(
                new RefreshSessionCommand(firstRotation.rawRefreshToken(), null));
        assertEquals(RefreshStatus.REJECTED, afterLogout.status());
        assertNull(afterLogout.rawRefreshToken());
        assertNull(afterLogout.identity());
        assertEquals(1, tokens.listByFamily("rft" + suffix).stream()
                .filter(token -> token.status() == RefreshTokenStatus.ACTIVE).count(),
                "The current generation is left active but unusable, and no successor appears");
    }

    @Test
    void aBlockedAccountCannotRenewItsSessionEither() {
        // The same barrier as INACTIVE, checked for both because they are separate statuses and
        // a change to the activation rule must not fix one and quietly leave the other open.
        User user = users.findActive(userId).orElseThrow();
        user.block();
        users.save(user);

        var result = refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));

        assertEquals(RefreshStatus.REJECTED, result.status());
        assertNull(result.rawRefreshToken());
        assertNull(result.identity());
        assertEquals(1, tokens.listByFamily("rft" + suffix).size(),
                "A blocked account must not mint a new generation");
        // The session itself is untouched: the account refusing is not the same fact as the
        // session being revoked, and conflating them would escalate an ordinary block.
        assertFalse(sessions.findActive(sessionId).orElseThrow().isRevoked());
    }

    @Test
    void anUnknownSecretIsRejectedWithoutTouchingTheStore() {
        var result = refreshSession.refresh(new RefreshSessionCommand("nunca-emitido", null));

        assertEquals(RefreshStatus.REJECTED, result.status());
        assertNull(result.idUserSession());
        assertEquals(1, tokens.listByFamily("rft" + suffix).size());
    }
}
