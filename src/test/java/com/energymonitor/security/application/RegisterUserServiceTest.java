package com.energymonitor.security.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.command.RegisterUserCommand;
import com.energymonitor.security.application.exception.EmailAlreadyRegisteredException;
import com.energymonitor.security.application.exception.PasswordPolicyViolationException;
import com.energymonitor.security.application.exception.UndeliverableEmailException;
import com.energymonitor.security.application.usecase.RegisterUserService;
import com.energymonitor.security.domain.model.PendingRegistration;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * {@code RegisterUser} requirements: keeps a registration waiting for its code, with the password
 * hashed; creates no person and no account; refuses taken addresses, mistyped or undeliverable
 * domains and policy-violating passwords.
 */
class RegisterUserServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-03-01T12:00:00Z"), ZoneOffset.UTC);

    private final UseCaseFixtures.FakeUserPersistencePort users = new UseCaseFixtures.FakeUserPersistencePort();
    private final UseCaseFixtures.FakePendingRegistrationPersistencePort pending =
            new UseCaseFixtures.FakePendingRegistrationPersistencePort();
    private final UseCaseFixtures.FakePasswordPolicyPersistencePort policies =
            new UseCaseFixtures.FakePasswordPolicyPersistencePort();
    private final UseCaseFixtures.FakePasswordHasherPort hasher = new UseCaseFixtures.FakePasswordHasherPort();
    private final UseCaseFixtures.FakeIdentifierGeneratorPort identifiers =
            new UseCaseFixtures.FakeIdentifierGeneratorPort();
    /** Domains that "cannot receive mail" in these tests; every other one can. */
    private final Set<String> deadDomains = new HashSet<>();
    private final List<String> checkedDomains = new ArrayList<>();
    private final RegisterUserService register =
            new RegisterUserService(users, pending, policies, hasher, identifiers,
                    domain -> {
                        checkedDomains.add(domain);
                        return !deadDomains.contains(domain);
                    },
                    CLOCK);

    private RegisterUserCommand command(String email, String password) {
        return new RegisterUserCommand(email, password, "Ada", "Lovelace",
                null, "10.0.0.1");
    }

    @Test
    void keepsTheRegistrationWithTheHashedPasswordUntilItIsVerified() {
        PendingRegistration registration =
                register.register(command("ada@example.com", UseCaseFixtures.PASSWORD));

        assertEquals("ada@example.com", registration.email().value());
        assertEquals("Ada", registration.name());
        assertTrue(hasher.matches(UseCaseFixtures.PASSWORD, registration.passwordHash()));
        assertEquals("10.0.0.1", registration.ipAddress().orElseThrow());
        assertEquals(CLOCK.instant().plus(PendingRegistration.LIFETIME), registration.expiresAt());
        assertEquals(List.of(registration), pending.registrations());
    }

    @Test
    void createsNoAccountBeforeTheAddressIsVerified() {
        register.register(command("ada@example.com", UseCaseFixtures.PASSWORD));

        assertTrue(users.users().isEmpty());
    }

    @Test
    void registeringAgainReplacesTheEarlierRequestAndItsIdentifier() {
        PendingRegistration first = register.register(command("ada@example.com", UseCaseFixtures.PASSWORD));
        PendingRegistration second = register.register(command("ADA@example.com", "StrongPass2!"));

        assertEquals(List.of(second), pending.registrations());
        // The code is derived from the identifier, so the first one stops working.
        assertNotEquals(first.idUser(), second.idUser());
        assertTrue(hasher.matches("StrongPass2!", second.passwordHash()));
    }

    @Test
    void rejectsPasswordBelowPolicy() {
        assertThrows(PasswordPolicyViolationException.class,
                () -> register.register(command("ada@example.com", "weak")));

        assertTrue(pending.registrations().isEmpty());
    }

    @Test
    void rejectsAnAddressThatAlreadyHasAnAccount() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);

        assertThrows(EmailAlreadyRegisteredException.class,
                () -> register.register(command("ADA@Example.com", UseCaseFixtures.PASSWORD)));
        assertTrue(pending.registrations().isEmpty());
    }

    @Test
    void refusesAnAddressWhoseDomainCannotReceiveMailAndKeepsNothing() {
        deadDomains.add("correo-inventado.co");

        UndeliverableEmailException error = assertThrows(UndeliverableEmailException.class,
                () -> register.register(command("Ana@Correo-Inventado.co", UseCaseFixtures.PASSWORD)));

        assertTrue(error.getMessage().contains("cannot receive mail"));
        assertEquals(List.of("correo-inventado.co"), checkedDomains);
        assertTrue(pending.registrations().isEmpty());
    }

    @Test
    void refusesAMistypedProviderEvenWhenItsDomainReceivesMail() {
        // meil.com is registered and publishes mail servers: only the spelling gives it away.
        UndeliverableEmailException error = assertThrows(UndeliverableEmailException.class,
                () -> register.register(command("bspc1507@meil.com", UseCaseFixtures.PASSWORD)));

        assertTrue(error.getMessage().contains("did you mean mail.com?"));
        assertTrue(checkedDomains.isEmpty());
        assertTrue(pending.registrations().isEmpty());
    }

    @Test
    void acceptsTheProvidersThemselves() {
        register.register(command("ada@gmail.com", UseCaseFixtures.PASSWORD));
        register.register(command("grace@soy.sena.edu.co", UseCaseFixtures.PASSWORD));

        assertEquals(2, pending.registrations().size());
        assertEquals(List.of("gmail.com", "soy.sena.edu.co"), checkedDomains);
    }

    @Test
    void checksTheDomainOnlyAfterTheCheapRefusals() {
        assertThrows(PasswordPolicyViolationException.class,
                () -> register.register(command("ada@example.com", "short")));

        assertTrue(checkedDomains.isEmpty());
    }
}
