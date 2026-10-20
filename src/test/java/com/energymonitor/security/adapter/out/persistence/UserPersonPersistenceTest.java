package com.energymonitor.security.adapter.out.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordHash;
import com.energymonitor.security.domain.model.Person;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserStatus;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

/**
 * Round trips of {@code person} and {@code user} through MySQL.
 *
 * <p>Each write is flushed and the persistence context cleared before reading back, so the
 * assertions exercise the real SQL columns, not cache hits. The transaction rolls back
 * afterwards, leaving the schema untouched.
 */
@SpringBootTest
@Transactional
class UserPersonPersistenceTest extends JwtKeyedTest {

    private static final Instant REGISTRATION = Instant.parse("2026-01-02T03:04:05Z");
    private static final String PERSON_ID = "per0000001";
    private static final String USER_ID = "use0000001";
    private static final String HASH =
            "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private PersonPersistenceAdapter persons;

    @Autowired
    private UserPersistenceAdapter users;

    private void flushAndClear() {
        entityManager.flush();
        entityManager.clear();
    }

    @Test
    void personNameRoundTripsAndRenamesPersist() {
        Person person = new Person(PERSON_ID, "Ada", "Lovelace");
        persons.save(person);
        flushAndClear();

        Person read = persons.findActive(PERSON_ID).orElseThrow();
        assertEquals("Ada", read.name());
        assertEquals("Lovelace", read.lastName());

        read.rename("Ada", "King");
        persons.save(read);
        flushAndClear();

        Person renamed = persons.findActive(PERSON_ID).orElseThrow();
        assertEquals("Ada", renamed.name());
        assertEquals("King", renamed.lastName());
    }

    @Test
    void theProfileImageRoundTripsOnTheAccount() {
        // The avatar belongs to user, so this is the column that must carry it now. Reading it
        // back through the persistence layer is what proves the column and the mapping agree.
        PersistenceFixtures.seedPerson(persons);
        User withAvatar = new User(USER_ID, PERSON_ID, PasswordHash.of(HASH),
                Email.of("ada@example.com"), true, REGISTRATION,
                UserStatus.ACTIVE, 0, null, "https://img/ada.png");
        users.save(withAvatar);
        flushAndClear();

        User read = users.findActive(USER_ID).orElseThrow();
        assertEquals("https://img/ada.png", read.profileImage().orElseThrow());
    }

    @Test
    void anAccountWithoutAvatarRoundTripsAsAbsent() {
        PersistenceFixtures.seedPerson(persons);
        users.save(new User(USER_ID, PERSON_ID, PasswordHash.of(HASH),
                Email.of("ada@example.com"), true, REGISTRATION,
                UserStatus.ACTIVE, 0, null, null));
        flushAndClear();

        assertTrue(users.findActive(USER_ID).orElseThrow().profileImage().isEmpty());
    }

    @Test
    void userWithNullLastLoginRoundTripsAndUpdates() {
        PersistenceFixtures.seedPerson(persons);
        User fresh = new User(USER_ID, PERSON_ID, PasswordHash.of(HASH),
                Email.of("ada@example.com"), false, REGISTRATION,
                UserStatus.INACTIVE, 0, null, null);
        users.save(fresh);
        flushAndClear();

        User read = users.findActive(USER_ID).orElseThrow();
        assertEquals(USER_ID, read.idUser());
        assertEquals(PERSON_ID, read.idPerson());
        assertEquals(HASH, read.passwordHash().value());
        assertEquals("ada@example.com", read.email().value());
        assertFalse(read.isEmailVerified());
        assertEquals(REGISTRATION, read.dateOfRegistration());
        assertEquals(UserStatus.INACTIVE, read.status());
        assertEquals(0, read.failedLoginAttempts());
        assertTrue(read.lastLoginAt().isEmpty());

        User revived = new User(USER_ID, PERSON_ID, PasswordHash.of(HASH),
                Email.of("ada@example.com"), true, REGISTRATION,
                UserStatus.ACTIVE, 2, Instant.parse("2026-03-01T12:30:45Z"), null);
        users.save(revived);
        flushAndClear();

        User updated = users.findActive(USER_ID).orElseThrow();
        assertTrue(updated.isEmailVerified());
        assertEquals(UserStatus.ACTIVE, updated.status());
        assertEquals(2, updated.failedLoginAttempts());
        assertEquals(Instant.parse("2026-03-01T12:30:45Z"), updated.lastLoginAt().orElseThrow());
    }

    @Test
    void findByEmailReturnsActiveAccount() {
        PersistenceFixtures.seedPerson(persons);
        users.save(new User(USER_ID, PERSON_ID, PasswordHash.of(HASH),
                Email.of("ada@example.com"), true, REGISTRATION,
                UserStatus.ACTIVE, 0, null, null));
        flushAndClear();

        User read = users.findActiveByEmail("ada@example.com").orElseThrow();
        assertEquals(USER_ID, read.idUser());
        assertEquals(Optional.empty(), users.findActiveByEmail("nobody@example.com"));
    }
}