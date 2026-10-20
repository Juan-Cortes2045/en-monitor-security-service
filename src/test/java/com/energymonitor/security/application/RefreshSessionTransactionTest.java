package com.energymonitor.security.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.willThrow;

import com.energymonitor.security.application.command.RefreshSessionCommand;
import com.energymonitor.security.application.port.in.RefreshSession;
import com.energymonitor.security.application.port.out.RefreshTokenPersistencePort;
import com.energymonitor.security.application.result.RefreshSessionResult;
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
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

/**
 * Proves a rotation is atomic against the real database rather than against an in-memory fake.
 *
 * <p>A fake cannot demonstrate this: it has no transaction, so a failure halfway through a
 * rotation leaves the in-memory objects half-mutated while the store still holds the old state.
 * That is a property of the fake, not of the design. Here the boundary is exercised for real,
 * with the token store replaced by a spy that fails the second write.
 *
 * <p>The invariant under test is the one an attacker or a bug would exploit: a retired
 * generation must never be left without the successor that replaced it. A credential that has
 * been spent with nothing issued in its place locks the user out while the theft remains
 * untraceable.
 */
@SpringBootTest
class RefreshSessionTransactionTest extends JwtKeyedTest {

    private static final Instant REGISTRATION = Instant.parse("2026-01-02T03:04:05Z");
    private static final Duration WEEK = Duration.ofDays(7);

    @Autowired
    private RefreshSession refreshSession;

    @Autowired
    private com.energymonitor.security.application.port.out.RefreshTokenHasherPort hasher;

    @Autowired
    private com.energymonitor.security.application.port.out.IdentifierGeneratorPort identifiers;

    @Autowired
    private com.energymonitor.security.application.port.out.UserSessionPersistencePort sessions;

    @Autowired
    private com.energymonitor.security.application.port.out.UserPersistencePort users;

    @Autowired
    private com.energymonitor.security.application.port.out.PersonPersistencePort persons;

    @Autowired
    private com.energymonitor.security.adapter.out.persistence.repository.RefreshTokenRepository
            tokenRepository;

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

    @MockitoSpyBean
    private RefreshTokenPersistencePort tokenPort;

    private String suffix;
    private String userId;
    private String personId;
    private String sessionId;
    private String rootSecret;

    @BeforeEach
    void seedAccountAndSession() {
        // Business keys are VARCHAR(10), so the suffix is trimmed to keep them valid.
        suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 7);
        personId = "per" + suffix;
        userId = "use" + suffix;
        sessionId = "ses" + suffix;
        rootSecret = "raiz-" + suffix;
        Instant now = Instant.now();

        persons.save(new Person(personId, "Ada", "Lovelace"));
        users.save(new User(userId, personId,
                PasswordHash.of("$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
                Email.of("rotacion-" + suffix + "@example.com"), true, REGISTRATION,
                UserStatus.ACTIVE, 0, null, null));
        sessions.save(UserSession.open(sessionId, userId,
                now, now.plus(WEEK), "10.0.0.1", "JUnit"));
        tokenPort.save(RefreshToken.root("rft" + suffix, sessionId, hasher.hash(rootSecret),
                now, now.plus(WEEK)));
    }

    @AfterEach
    void cleanUp() {
        // These tests cannot run inside a transaction, because the rollback they assert on is
        // the one the application opens for itself. That means the rows they commit have to be
        // removed by hand, in foreign key order, or the database grows a little every run.
        //
        // refresh_token is self-referencing, so the links are severed before the rows go:
        // deleting a parent while a child still points at it violates the constraint.
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

    @Test
    void aSuccessfulRotationCommitsTheRetiredGenerationAndItsSuccessorTogether() {
        RefreshSessionResult result = refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));

        assertTrue(result.issued());
        RefreshToken retired = tokenPort.findByTokenHash(hasher.hash(rootSecret)).orElseThrow();
        RefreshToken successor = tokenPort
                .findByTokenHash(hasher.hash(result.rawRefreshToken())).orElseThrow();
        assertEquals(RefreshTokenStatus.ROTATED, retired.status());
        assertEquals(RefreshTokenStatus.ACTIVE, successor.status());
        assertEquals(retired.idRefreshToken(), successor.parentId().orElseThrow());
        assertEquals(retired.familyId(), successor.familyId());
    }

    @Test
    void aFailureWhileWritingTheSuccessorRollsBackTheRetirementToo() {
        // The successor write fails after the presented generation has already been retired in
        // memory. Without the transaction boundary the row would be left rotated with no
        // replacement, which is the inconsistent state this test exists to rule out.
        willThrow(new IllegalStateException("simulated storage failure"))
                .given(tokenPort).save(any());

        assertThrows(IllegalStateException.class,
                () -> refreshSession.refresh(new RefreshSessionCommand(rootSecret, null)));

        RefreshToken afterRollback = tokenPort.findByTokenHash(hasher.hash(rootSecret))
                .orElseThrow();
        assertEquals(RefreshTokenStatus.ACTIVE, afterRollback.status(),
                "The generation must not stay retired without a successor");
        assertTrue(afterRollback.rotatedAt().isEmpty());
        assertEquals(1, tokenPort.listByFamily(afterRollback.familyId()).size(),
                "No orphan successor may survive the rollback");
    }

    @Test
    void theSessionSlidesWithoutBecomingASecondLogin() {
        int before = sessions.listActiveByUser(userId).size();

        RefreshSessionResult result = refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));

        assertEquals(sessionId, result.idUserSession());
        assertEquals(before, sessions.listActiveByUser(userId).size(),
                "Rotating a secret must not open another session");
        assertNotNull(sessions.findActive(sessionId).orElseThrow().expirationAt());
    }

    @Test
    void aReuseCommittedToTheDatabaseRevokesTheFamilyAndTheSession() {
        RefreshSessionResult first = refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));
        assertTrue(first.issued());

        RefreshSessionResult replay = refreshSession.refresh(
                new RefreshSessionCommand(rootSecret, "198.51.100.9"));

        assertEquals(RefreshStatus.REUSE_DETECTED,
                replay.status());
        RefreshToken successor = tokenPort
                .findByTokenHash(hasher.hash(first.rawRefreshToken())).orElseThrow();
        assertEquals(RefreshTokenStatus.REVOKED, successor.status(),
                "The current generation of a compromised family must not stay active");
        assertEquals(RevocationReason.REFRESH_TOKEN_REUSE, successor.revokedReason().orElseThrow());
        var session = sessions.findActive(sessionId).orElseThrow();
        assertTrue(session.isRevoked());
        assertEquals(RevocationReason.REFRESH_TOKEN_REUSE,
                session.revokedReason().orElseThrow());
    }

    @Test
    void onlyTheHashIsEverStored() {
        RefreshSessionResult result = refreshSession.refresh(new RefreshSessionCommand(rootSecret, null));

        String storedRoot = tokenPort.findByTokenHash(hasher.hash(rootSecret)).orElseThrow()
                .tokenHash();
        String storedSuccessor = tokenPort
                .findByTokenHash(hasher.hash(result.rawRefreshToken())).orElseThrow().tokenHash();
        assertEquals(64, storedRoot.length());
        assertEquals(64, storedSuccessor.length());
        assertTrue(storedRoot.matches("[0-9a-f]{64}"));
        assertTrue(storedSuccessor.matches("[0-9a-f]{64}"));
    }

    @Test
    void anUnknownSecretResolvesToNothingWithoutTouchingTheStore() {
        RefreshSessionResult result = refreshSession.refresh(
                new RefreshSessionCommand("nunca-emitido-" + suffix, null));

        assertEquals(RefreshStatus.REJECTED,
                result.status());
        assertEquals(1, tokenPort.listByFamily("rft" + suffix).size(),
                "A rejected attempt must not create a generation");
    }
}
