package com.energymonitor.security.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.api.AccountRegistered;
import com.energymonitor.security.application.command.RegisterUserCommand;
import com.energymonitor.security.application.exception.EmailAlreadyRegisteredException;
import com.energymonitor.security.application.exception.PasswordPolicyViolationException;
import com.energymonitor.security.application.usecase.RegisterUserService;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * {@code RegisterUser} requirements: hashes through the hasher port, persists person and user,
 * rejects duplicate addresses and policy-violating passwords.
 */
class RegisterUserServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-03-01T12:00:00Z"), ZoneOffset.UTC);

    private final UseCaseFixtures.FakeUserPersistencePort users = new UseCaseFixtures.FakeUserPersistencePort();
    private final UseCaseFixtures.FakePersonPersistencePort persons = new UseCaseFixtures.FakePersonPersistencePort();
    private final UseCaseFixtures.FakePasswordPolicyPersistencePort policies =
            new UseCaseFixtures.FakePasswordPolicyPersistencePort();
    private final UseCaseFixtures.FakePasswordHasherPort hasher = new UseCaseFixtures.FakePasswordHasherPort();
    private final UseCaseFixtures.FakeIdentifierGeneratorPort identifiers =
            new UseCaseFixtures.FakeIdentifierGeneratorPort();
    private final UseCaseFixtures.FakeAuditLogPersistencePort audits =
            new UseCaseFixtures.FakeAuditLogPersistencePort();
    private final UseCaseFixtures.FakeAccountEventPublisherPort events =
            new UseCaseFixtures.FakeAccountEventPublisherPort();
    private final RegisterUserService register =
            new RegisterUserService(users, persons, policies, hasher, identifiers, audits, events,
                    CLOCK);

    private RegisterUserCommand command(String email, String password) {
        return new RegisterUserCommand(email, password, "Ada", "Lovelace",
                null, "10.0.0.1");
    }

    @Test
    void registersActiveUserWithHashedPasswordAndCreatesPerson() {
        User user = register.register(command("ada@example.com", UseCaseFixtures.PASSWORD));

        assertEquals(UserStatus.ACTIVE, user.status());
        assertTrue(hasher.matches(UseCaseFixtures.PASSWORD, user.passwordHash()));
        assertTrue(persons.findActive(user.idPerson()).isPresent());
        assertTrue(users.findActive(user.idUser()).isPresent());
    }

    @Test
    void announcesTheNewAccountSoAdministratorsAreTold() {
        User user = register.register(command("ada@example.com", UseCaseFixtures.PASSWORD));

        assertEquals(List.of(new AccountRegistered(user.idUser(), "ada@example.com", CLOCK.instant())),
                events.eventsOf(AccountRegistered.class));
    }

    @Test
    void announcesNothingWhenTheRegistrationIsRefused() {
        assertThrows(PasswordPolicyViolationException.class,
                () -> register.register(command("ada@example.com", "short")));

        assertTrue(events.events().isEmpty());
    }

    @Test
    void recordsACreateAuditEntryPointingAtTheNewUser() {
        User user = register.register(command("ada@example.com", UseCaseFixtures.PASSWORD));

        assertEquals(1, audits.logs().size());
        assertEquals(AuditAction.CREATE, audits.logs().getFirst().action());
        assertEquals(user.idUser(), audits.logs().getFirst().idUser().orElseThrow());
    }

    @Test
    void rejectsPasswordBelowPolicy() {
        PasswordPolicyViolationException error = assertThrows(
                PasswordPolicyViolationException.class,
                () -> register.register(command("ada@example.com", "weak")));
        assertNotNull(error);
        assertTrue(persons.findActive("id0000001").isEmpty());
        assertTrue(users.findActive("id0000002").isEmpty());
    }

    @Test
    void rejectsRegisteredEmail() {
        register.register(command("ada@example.com", UseCaseFixtures.PASSWORD));

        EmailAlreadyRegisteredException error = assertThrows(
                EmailAlreadyRegisteredException.class,
                () -> register.register(command("ada@example.com", UseCaseFixtures.PASSWORD)));
        assertNotNull(error);
        assertEquals(1, users.users().size());
    }

    @Test
    void normalisesEmailCaseBeforeUniquenessCheck() {
        register.register(command("ada@example.com", UseCaseFixtures.PASSWORD));

        EmailAlreadyRegisteredException error = assertThrows(
                EmailAlreadyRegisteredException.class,
                () -> register.register(command("ADA@Example.com", UseCaseFixtures.PASSWORD)));
        assertNotNull(error);
        assertEquals(1, users.users().size());
    }
}