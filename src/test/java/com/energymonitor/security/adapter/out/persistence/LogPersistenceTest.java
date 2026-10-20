package com.energymonitor.security.adapter.out.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.adapter.out.persistence.entity.LoginErrorLogEntity;
import com.energymonitor.security.adapter.out.persistence.repository.LoginErrorLogRepository;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.LoginErrorLog;
import com.energymonitor.security.domain.model.LoginErrorType;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

/**
 * Round trips of the two append-only logs.
 *
 * <p>Both map their business event time into {@code created_at}, so the stored instant must
 * equal the domain {@code occurredAt} after a flush, clear and reload.
 */
@SpringBootTest
@Transactional
class LogPersistenceTest extends JwtKeyedTest {

    private static final String USER_ID = "use0000001";
    private static final String AUDIT_ID = "aud0000001";
    private static final String ERROR_ID = "err0000001";
    private static final Instant OCCURRED_AT = Instant.parse("2026-04-12T18:05:00Z");

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private AuditLogPersistenceAdapter auditLogs;

    @Autowired
    private LoginErrorLogPersistenceAdapter loginErrorLogs;

    @Autowired
    private LoginErrorLogRepository loginErrorLogRepository;

    @Autowired
    private PersonPersistenceAdapter persons;

    @Autowired
    private UserPersistenceAdapter users;

    private void flushAndClear() {
        entityManager.flush();
        entityManager.clear();
    }

    @Test
    void auditLogRoundTripsWithEventTimeAndOptionalFields() {
        PersistenceFixtures.seedUser(persons, users);
        auditLogs.save(new AuditLog(AUDIT_ID, USER_ID, AuditAction.LOGIN,
                "Successful login", "10.0.0.5", "energy-monitor", OCCURRED_AT));
        flushAndClear();

        AuditLog read = auditLogs.findActive(AUDIT_ID).orElseThrow();
        assertEquals(AUDIT_ID, read.idAuditLog());
        assertEquals(USER_ID, read.idUser().orElseThrow());
        assertEquals(AuditAction.LOGIN, read.action());
        assertEquals("Successful login", read.description().orElseThrow());
        assertEquals("10.0.0.5", read.ipAddress().orElseThrow());
        assertEquals("energy-monitor", read.application().orElseThrow());
        assertEquals(OCCURRED_AT, read.occurredAt());
    }

    @Test
    void auditLogWithoutActorKeepsNullUser() {
        auditLogs.save(new AuditLog(AUDIT_ID, null, AuditAction.DELETE,
                "Purged old data", null, "batch", OCCURRED_AT));
        flushAndClear();

        AuditLog read = auditLogs.findActive(AUDIT_ID).orElseThrow();
        assertTrue(read.idUser().isEmpty());
        assertTrue(read.ipAddress().isEmpty());
        assertEquals(AuditAction.DELETE, read.action());
        assertEquals(OCCURRED_AT, read.occurredAt());
    }

    @Test
    void userNotFoundErrorKeepsNullUserAndRoundTrips() {
        loginErrorLogs.save(LoginErrorLog.userNotFound(ERROR_ID, "10.0.0.9", OCCURRED_AT));
        flushAndClear();

        LoginErrorLog read = loginErrorLogs.findActive(ERROR_ID).orElseThrow();
        assertEquals(LoginErrorType.USER_NOT_FOUND, read.errorType());
        assertTrue(read.idUser().isEmpty());
        assertEquals("10.0.0.9", read.ipAddress().orElseThrow());
        assertTrue(read.description().isEmpty());
        assertEquals(OCCURRED_AT, read.occurredAt());
    }

    @Test
    void invalidPasswordErrorPreservesUser() {
        PersistenceFixtures.seedUser(persons, users);
        loginErrorLogs.save(new LoginErrorLog(ERROR_ID, USER_ID, LoginErrorType.INVALID_PASSWORD,
                "Wrong password", "10.0.0.4", OCCURRED_AT));
        flushAndClear();

        LoginErrorLog read = loginErrorLogs.findActive(ERROR_ID).orElseThrow();
        assertEquals(LoginErrorType.INVALID_PASSWORD, read.errorType());
        assertEquals(USER_ID, read.idUser().orElseThrow());
        assertEquals("Wrong password", read.description().orElseThrow());
    }

    @Test
    void corruptRowMissingRequiredUserIsRejectedOnReload() {
        PersistenceFixtures.seedUser(persons, users);
        // Plant a row whose classification REQUIRES a known user ({@code INVALID_PASSWORD})
        // but that carries {@code null} in user_id, bypassing the domain constructor that
        // would refuse it. Reading it back must fail loudly: the row violates a domain
        // invariant and cannot rehydrate.
        LoginErrorLogEntity corrupt = new LoginErrorLogEntity();
        corrupt.setIdLoginError(ERROR_ID);
        corrupt.setUserId(null);
        corrupt.setErrorType(LoginErrorType.INVALID_PASSWORD);
        corrupt.setDescription(null);
        corrupt.setIpAddress(null);
        corrupt.setCreatedAt(OCCURRED_AT);
        loginErrorLogRepository.save(corrupt);
        flushAndClear();

        assertThrows(IllegalArgumentException.class, () -> loginErrorLogs.findActive(ERROR_ID));
    }
}