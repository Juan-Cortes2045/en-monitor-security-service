package com.energymonitor.security.adapter.out.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordHash;
import com.energymonitor.security.domain.model.PendingRegistration;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

/**
 * Round trips of {@code pending_registration} through MySQL. The transaction rolls back
 * afterwards, leaving the schema untouched.
 */
@SpringBootTest
@Transactional
class PendingRegistrationPersistenceTest extends JwtKeyedTest {

    private static final Instant REQUESTED = Instant.parse("2026-01-02T03:04:05.123456Z");
    private static final String HASH =
            "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private PendingRegistrationPersistenceAdapter registrations;

    private PendingRegistration request(String idUser, String email, Instant at) {
        return PendingRegistration.request(idUser, Email.of(email), "Ada", "Lovelace",
                PasswordHash.of(HASH), null, "10.0.0.7", at);
    }

    private void flushAndClear() {
        entityManager.flush();
        entityManager.clear();
    }

    @Test
    void aRegistrationRoundTripsWithEveryColumn() {
        registrations.save(request("pen0000001", "pending-a@example.com", REQUESTED));
        flushAndClear();

        PendingRegistration read =
                registrations.findByEmail(Email.of("pending-a@example.com")).orElseThrow();
        assertEquals("pen0000001", read.idUser());
        assertEquals("Ada", read.name());
        assertEquals("Lovelace", read.lastName().orElseThrow());
        assertEquals(HASH, read.passwordHash().value());
        assertEquals("10.0.0.7", read.ipAddress().orElseThrow());
        assertEquals(REQUESTED, read.requestedAt());
        assertEquals(REQUESTED.plus(PendingRegistration.LIFETIME), read.expiresAt());
    }

    @Test
    void registeringTheSameAddressAgainReplacesTheEarlierRequest() {
        registrations.save(request("pen0000002", "pending-b@example.com", REQUESTED));
        registrations.save(request("pen0000003", "pending-b@example.com", REQUESTED.plusSeconds(60)));
        flushAndClear();

        assertEquals("pen0000003",
                registrations.findByEmail(Email.of("pending-b@example.com")).orElseThrow().idUser());
        assertTrue(entityManager.find(
                com.energymonitor.security.adapter.out.persistence.entity.PendingRegistrationEntity.class,
                "pen0000002") == null);
    }

    @Test
    void thePurgeRemovesOnlyTheExpiredRequests() {
        Instant now = REQUESTED.plus(PendingRegistration.LIFETIME);
        registrations.save(request("pen0000004", "pending-c@example.com", REQUESTED));
        registrations.save(request("pen0000005", "pending-d@example.com", REQUESTED.plusSeconds(1)));
        flushAndClear();

        // At least ours: a development database may hold other expired requests.
        assertTrue(registrations.deleteExpired(now) >= 1);
        assertTrue(registrations.findByEmail(Email.of("pending-c@example.com")).isEmpty());
        assertTrue(registrations.findByEmail(Email.of("pending-d@example.com")).isPresent());
    }

    @Test
    void aVerifiedRequestIsDeleted() {
        registrations.save(request("pen0000006", "pending-e@example.com", REQUESTED));
        flushAndClear();

        registrations.delete("pen0000006");
        flushAndClear();

        assertTrue(registrations.findByEmail(Email.of("pending-e@example.com")).isEmpty());
    }
}
