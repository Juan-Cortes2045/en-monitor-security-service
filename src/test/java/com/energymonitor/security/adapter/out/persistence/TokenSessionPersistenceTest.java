package com.energymonitor.security.adapter.out.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.adapter.out.persistence.support.Instants;
import com.energymonitor.security.domain.model.PasswordResetToken;
import com.energymonitor.security.domain.model.RevocationReason;
import com.energymonitor.security.domain.model.UserSession;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import jakarta.persistence.EntityManager;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Round trips of the time-boxed credentials: password reset tokens and user sessions.
 *
 * <p>The lifecycle flags are the security-sensitive part: {@code used} on a token and
 * {@code revoked}/{@code closedAt} on a session must come back exactly as persisted, or a
 * consumed credential would rehydrate as usable. The other half of the token's contract is that
 * only its hash crosses this boundary, which is checked here against the real schema.
 */
@SpringBootTest
@Transactional
class TokenSessionPersistenceTest extends JwtKeyedTest {

    private static final String USER_ID = "use0000001";
    private static final String TOKEN_ID = "tok0000001";
    private static final String SESSION_ID = "ses0000001";
    private static final String CLEAR_TOKEN = "reset-value-1234567890";
    private static final String REFRESH_TOKEN = "refresh-value-1234567890";
    private static final Instant OPENED_AT = Instant.parse("2026-02-01T08:00:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2026-03-01T08:00:00Z");
    private static final Instant CLOSED_AT = Instant.parse("2026-02-02T09:30:00Z");

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private PersonPersistenceAdapter persons;

    @Autowired
    private UserPersistenceAdapter users;

    @Autowired
    private PasswordResetTokenPersistenceAdapter passwordResetTokens;

    @Autowired
    private com.energymonitor.security.application.port.out.PasswordResetTokenHasherPort
            resetTokenHasher;

    @Autowired
    private UserSessionPersistenceAdapter userSessions;
    @Autowired
    private PlatformTransactionManager transactions;

    private void flushAndClear() {
        entityManager.flush();
        entityManager.clear();
    }

    /**
     * The digest is bound to the account, so both arguments are needed to reproduce it. This is the
     * form the production adapter receives too, which is why the helper exists rather than the test
     * spelling the two arguments at every call site.
     */
    private String hashOf(String clearToken) {
        return resetTokenHasher.hash(USER_ID, clearToken);
    }

    @Test
    void tokenUsedFlagSurvivesInsertUpdateAndReload() {
        PersistenceFixtures.seedUser(persons, users);
        PasswordResetToken issued = PasswordResetToken.issue(TOKEN_ID, USER_ID, CLEAR_TOKEN,
                hashOf(CLEAR_TOKEN), OPENED_AT, EXPIRES_AT);
        passwordResetTokens.save(issued);
        flushAndClear();

        PasswordResetToken read = passwordResetTokens.findActiveByHash(hashOf(CLEAR_TOKEN))
                .orElseThrow();
        assertEquals(TOKEN_ID, read.idResetToken());
        assertEquals(USER_ID, read.idUser());
        assertEquals(OPENED_AT, read.createdAt());
        assertEquals(EXPIRES_AT, read.expirationAt());
        assertFalse(read.isUsed());

        PasswordResetToken consumed = PasswordResetToken.rehydrate(TOKEN_ID, USER_ID,
                hashOf(CLEAR_TOKEN), OPENED_AT, EXPIRES_AT, true, 0);
        passwordResetTokens.update(consumed);
        flushAndClear();

        PasswordResetToken stored = passwordResetTokens.findActive(TOKEN_ID).orElseThrow();
        assertTrue(stored.isUsed());
        assertEquals(OPENED_AT, stored.createdAt());
    }

    @Test
    void onlyTheHashOfAResetTokenReachesTheDatabase() {
        PersistenceFixtures.seedUser(persons, users);
        PasswordResetToken issued = PasswordResetToken.issue(TOKEN_ID, USER_ID, CLEAR_TOKEN,
                hashOf(CLEAR_TOKEN), OPENED_AT, EXPIRES_AT);
        passwordResetTokens.save(issued);
        flushAndClear();

        // Read the row the way an incident investigation would: straight out of the table,
        // bypassing every mapper and every accessor the application offers.
        Object stored = entityManager.createNativeQuery(
                        "SELECT reset_token_hash FROM password_reset_token WHERE id_reset_token = ?1")
                .setParameter(1, TOKEN_ID)
                .getSingleResult();
        assertEquals(hashOf(CLEAR_TOKEN), stored);
        assertEquals(64, ((String) stored).length());

        // And the clear secret that issued it comes back as nothing at all.
        PasswordResetToken reloaded = passwordResetTokens.findActiveByHash(hashOf(CLEAR_TOKEN))
                .orElseThrow();
        assertTrue(reloaded.clearToken().isEmpty(),
                "A token read back from the database must not carry a secret");
    }

    @Test
    void openSessionRoundTripsAndKeepAllFieldsOnReload() {
        PersistenceFixtures.seedUser(persons, users);
        userSessions.save(UserSession.open(SESSION_ID, USER_ID, OPENED_AT, EXPIRES_AT, null, null));
        flushAndClear();

        UserSession read = userSessions.findActive(SESSION_ID).orElseThrow();
        assertEquals(SESSION_ID, read.idUserSession());
        assertEquals(USER_ID, read.idUser());
        assertEquals(OPENED_AT, read.createdAt());
        assertEquals(EXPIRES_AT, read.expirationAt());
        assertTrue(read.ipAddress().isEmpty());
        assertTrue(read.userAgent().isEmpty());
        assertFalse(read.isRevoked());
        assertTrue(read.closedAt().isEmpty());
    }

    @Test
    void closedSessionKeepsRevokedFlagAndClosureInstant() {
        PersistenceFixtures.seedUser(persons, users);
        UserSession session = UserSession.open(SESSION_ID, USER_ID,
                OPENED_AT, EXPIRES_AT, "192.168.1.10", "test-agent");
        session.revoke(OPENED_AT.plusSeconds(120), RevocationReason.PASSWORD_CHANGED);
        session.close(CLOSED_AT);
        userSessions.save(session);
        flushAndClear();

        UserSession read = userSessions.findActive(SESSION_ID).orElseThrow();
        assertTrue(read.isRevoked());
        assertEquals(CLOSED_AT, read.closedAt().orElseThrow());
        assertEquals("192.168.1.10", read.ipAddress().orElseThrow());
        assertEquals("test-agent", read.userAgent().orElseThrow());
        assertEquals(OPENED_AT, read.createdAt());
    }

    @Test
    void revokedSessionRoundTripsInstantAndReason() {
        PersistenceFixtures.seedUser(persons, users);
        UserSession session = UserSession.open(SESSION_ID, USER_ID,
                OPENED_AT, EXPIRES_AT, "192.168.1.10", "test-agent");
        Instant revokedAt = OPENED_AT.plusSeconds(300);
        session.revoke(revokedAt, RevocationReason.REFRESH_TOKEN_REUSE);
        userSessions.save(session);
        flushAndClear();

        UserSession read = userSessions.findActive(SESSION_ID).orElseThrow();
        assertTrue(read.isRevoked());
        assertEquals(revokedAt, read.revokedAt().orElseThrow());
        assertEquals(RevocationReason.REFRESH_TOKEN_REUSE, read.revokedReason().orElseThrow());
        // Revoking is not closing: the two stay distinguishable in the row.
        assertTrue(read.closedAt().isEmpty());
    }

    @Test
    void rotatedSessionKeepsItsIdentityAndSlidesOnlyTheWindow() {
        PersistenceFixtures.seedUser(persons, users);
        UserSession session = UserSession.open(SESSION_ID, USER_ID,
                OPENED_AT, EXPIRES_AT, "192.168.1.10", "test-agent");
        Instant rotatedAt = OPENED_AT.plusSeconds(3600);
        Instant newExpiration = EXPIRES_AT.plus(Duration.ofDays(7));
        session.rotate(newExpiration, rotatedAt);
        userSessions.save(session);
        flushAndClear();

        UserSession read = userSessions.findActive(SESSION_ID).orElseThrow();
        assertEquals(Instants.truncate(newExpiration), read.expirationAt());
        // Rotation slides the login, never replaces it: no second session is created.
        assertEquals(SESSION_ID, read.idUserSession());
        assertEquals(USER_ID, read.idUser());
        assertEquals(OPENED_AT, read.createdAt());
        assertTrue(read.isActive(rotatedAt));
    }
}
