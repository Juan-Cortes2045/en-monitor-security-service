package com.energymonitor.security.adapter.out.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.domain.model.RefreshToken;
import com.energymonitor.security.domain.model.RefreshTokenStatus;
import com.energymonitor.security.domain.model.RevocationReason;
import com.energymonitor.security.domain.model.UserSession;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

/**
 * Round trips of {@code refresh_token} and the revocation columns of {@code user_session} against
 * MySQL.
 *
 * <p>Each write is flushed and the persistence context cleared before reading back, so the
 * assertions exercise the real columns rather than cached objects. The transaction rolls back
 * afterwards, leaving the schema untouched.
 */
@SpringBootTest
@Transactional
class RefreshTokenPersistenceTest extends JwtKeyedTest {

    private static final String SESSION_ID = "ses0000001";
    private static final Instant OPENED_AT = Instant.parse("2026-05-01T10:00:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2026-05-08T10:00:00Z");
    private static final String HASH_ROOT = "1a".repeat(32);
    private static final String HASH_CHILD = "2b".repeat(32);

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private RefreshTokenPersistenceAdapter tokens;

    @Autowired
    private UserSessionPersistenceAdapter userSessions;

    @Autowired
    private PersonPersistenceAdapter persons;

    @Autowired
    private UserPersistenceAdapter users;

    private void flushAndClear() {
        entityManager.flush();
        entityManager.clear();
    }

    private void seedSession() {
        PersistenceFixtures.seedUser(persons, users);
        userSessions.save(UserSession.open(SESSION_ID, PersistenceFixtures.USER_ID, OPENED_AT,
                EXPIRES_AT, null, null));
    }

    @Test
    void rootGenerationRoundTripsEveryColumn() {
        seedSession();
        tokens.save(RefreshToken.root("rft0000001", SESSION_ID, HASH_ROOT, OPENED_AT, EXPIRES_AT));
        flushAndClear();

        RefreshToken read = tokens.findByTokenHash(HASH_ROOT).orElseThrow();
        assertEquals("rft0000001", read.idRefreshToken());
        assertEquals(SESSION_ID, read.idUserSession());
        assertEquals("rft0000001", read.familyId());
        assertTrue(read.parentId().isEmpty());
        assertEquals(RefreshTokenStatus.ACTIVE, read.status());
        assertEquals(OPENED_AT, read.createdAt());
        assertEquals(EXPIRES_AT, read.expiresAt());
        assertTrue(read.rotatedAt().isEmpty());
        assertTrue(read.revokedAt().isEmpty());
        assertTrue(read.revokedReason().isEmpty());
    }

    @Test
    void childGenerationCarriesItsLineage() {
        seedSession();
        RefreshToken root = RefreshToken.root("rft0000001", SESSION_ID, HASH_ROOT, OPENED_AT,
                EXPIRES_AT);
        tokens.save(root);
        RefreshToken child = RefreshToken.childOf(root, "rft0000002", HASH_CHILD,
                EXPIRES_AT, EXPIRES_AT.plusSeconds(604800));
        tokens.save(child);
        flushAndClear();

        RefreshToken read = tokens.findByTokenHash(HASH_CHILD).orElseThrow();
        assertEquals("rft0000001", read.parentId().orElseThrow());
        assertEquals("rft0000001", read.familyId());
        assertFalse(read.isRoot());
    }

    @Test
    void aThreeGenerationChainStaysInOneFamily() {
        seedSession();
        RefreshToken first = RefreshToken.root("rft0000001", SESSION_ID, HASH_ROOT, OPENED_AT,
                EXPIRES_AT);
        tokens.save(first);
        first.rotate(OPENED_AT.plusSeconds(60));
        tokens.save(first);

        RefreshToken second = RefreshToken.childOf(first, "rft0000002", HASH_CHILD,
                EXPIRES_AT, EXPIRES_AT.plusSeconds(604800));
        tokens.save(second);
        second.rotate(EXPIRES_AT);
        tokens.save(second);

        RefreshToken third = RefreshToken.childOf(second, "rft0000003", "3c".repeat(32),
                EXPIRES_AT, EXPIRES_AT.plusSeconds(1209600));
        tokens.save(third);
        flushAndClear();

        List<RefreshToken> family = tokens.listByFamily("rft0000001");
        assertEquals(3, family.size());
        assertTrue(family.stream().allMatch(token -> token.familyId().equals("rft0000001")));

        RefreshToken readRoot = tokens.findByTokenHash(HASH_ROOT).orElseThrow();
        RefreshToken readSecond = tokens.findByTokenHash(HASH_CHILD).orElseThrow();
        RefreshToken readThird = tokens.findByTokenHash("3c".repeat(32)).orElseThrow();

        // One chain: the root has no predecessor, each later generation points at the one
        // before it, and the retirement of each is remembered.
        assertTrue(readRoot.parentId().isEmpty());
        assertEquals(readRoot.idRefreshToken(), readSecond.parentId().orElseThrow());
        assertEquals(readSecond.idRefreshToken(), readThird.parentId().orElseThrow());
        assertEquals(RefreshTokenStatus.ROTATED, readRoot.status());
        assertEquals(RefreshTokenStatus.ROTATED, readSecond.status());
        assertEquals(RefreshTokenStatus.ACTIVE, readThird.status());
    }

    @Test
    void rotationPersistsTheStatusAndTheInstant() {
        seedSession();
        RefreshToken token = RefreshToken.root("rft0000001", SESSION_ID, HASH_ROOT, OPENED_AT,
                EXPIRES_AT);
        tokens.save(token);
        Instant rotatedAt = OPENED_AT.plusSeconds(120);
        token.rotate(rotatedAt);
        tokens.save(token);
        flushAndClear();

        RefreshToken read = tokens.findByTokenHash(HASH_ROOT).orElseThrow();
        assertEquals(RefreshTokenStatus.ROTATED, read.status());
        assertEquals(rotatedAt, read.rotatedAt().orElseThrow());
        // A retired generation stays findable: that is what makes its replay recognisable.
        assertTrue(read.tokenHash().equals(HASH_ROOT));
    }

    @Test
    void revocationPersistsTheInstantAndTheReason() {
        seedSession();
        RefreshToken token = RefreshToken.root("rft0000001", SESSION_ID, HASH_ROOT, OPENED_AT,
                EXPIRES_AT);
        tokens.save(token);
        Instant revokedAt = OPENED_AT.plusSeconds(300);
        token.revoke(revokedAt, RevocationReason.REFRESH_TOKEN_REUSE);
        tokens.save(token);
        flushAndClear();

        RefreshToken read = tokens.findByTokenHash(HASH_ROOT).orElseThrow();
        assertEquals(RefreshTokenStatus.REVOKED, read.status());
        assertEquals(revokedAt, read.revokedAt().orElseThrow());
        assertEquals(RevocationReason.REFRESH_TOKEN_REUSE, read.revokedReason().orElseThrow());
    }

    @Test
    void lookupByHashFindsNothingForAnUnknownSecret() {
        seedSession();

        assertTrue(tokens.findByTokenHash("f".repeat(64)).isEmpty());
    }

    @Test
    void theSameHashCannotBeStoredTwice() {
        seedSession();
        tokens.save(RefreshToken.root("rft0000001", SESSION_ID, HASH_ROOT, OPENED_AT, EXPIRES_AT));
        flushAndClear();

        // uk_refresh_token_hash: two generations sharing a hash would make a lookup ambiguous.
        org.junit.jupiter.api.Assertions.assertThrows(RuntimeException.class, () -> {
            tokens.save(RefreshToken.root("rft0000009", SESSION_ID, HASH_ROOT, OPENED_AT,
                    EXPIRES_AT));
            entityManager.flush();
        });
    }

    @Test
    void onlyTheHashIsStoredSoTheSecretCannotBeReadBack() {
        seedSession();
        tokens.save(RefreshToken.root("rft0000001", SESSION_ID, HASH_ROOT, OPENED_AT, EXPIRES_AT));
        flushAndClear();

        String column = (String) entityManager
                .createNativeQuery("SELECT token_hash FROM refresh_token WHERE id_refresh_token = ?")
                .setParameter(1, "rft0000001")
                .getSingleResult();

        assertEquals(HASH_ROOT, column);
        assertEquals(64, column.length());
    }

    @Test
    void sessionRevocationColumnsRoundTrip() {
        seedSession();
        UserSession session = userSessions.findActive(SESSION_ID).orElseThrow();
        Instant revokedAt = OPENED_AT.plusSeconds(200);
        session.revoke(revokedAt, RevocationReason.ADMINISTRATIVE);
        userSessions.save(session);
        flushAndClear();

        UserSession read = userSessions.findActive(SESSION_ID).orElseThrow();
        assertTrue(read.isRevoked());
        assertEquals(revokedAt, read.revokedAt().orElseThrow());
        assertEquals(RevocationReason.ADMINISTRATIVE, read.revokedReason().orElseThrow());
        assertTrue(read.closedAt().isEmpty());
    }

    @Test
    void anOpenSessionHasNoRevocationRecord() {
        seedSession();
        userSessions.save(UserSession.open(SESSION_ID, PersistenceFixtures.USER_ID, OPENED_AT,
                EXPIRES_AT, null, null));
        flushAndClear();

        UserSession read = userSessions.findActive(SESSION_ID).orElseThrow();
        assertFalse(read.isRevoked());
        assertTrue(read.revokedAt().isEmpty());
        assertTrue(read.revokedReason().isEmpty());
    }
}
