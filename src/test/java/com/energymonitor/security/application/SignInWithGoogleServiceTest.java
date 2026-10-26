package com.energymonitor.security.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.UseCaseFixtures.FakeAuditLogPersistencePort;
import com.energymonitor.security.application.UseCaseFixtures.FakeIdentifierGeneratorPort;
import com.energymonitor.security.application.UseCaseFixtures.FakePasswordHasherPort;
import com.energymonitor.security.application.UseCaseFixtures.FakePersonPersistencePort;
import com.energymonitor.security.application.UseCaseFixtures.FakeTokenGeneratorPort;
import com.energymonitor.security.application.UseCaseFixtures.FakeUserPersistencePort;
import com.energymonitor.security.application.exception.AccountNotActiveException;
import com.energymonitor.security.api.AccountRegistered;
import com.energymonitor.security.application.exception.EmailAlreadyRegisteredException;
import com.energymonitor.security.application.exception.TermsNotAcceptedException;
import com.energymonitor.security.application.result.GoogleIdentity;
import com.energymonitor.security.application.usecase.SignInWithGoogleService;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordHash;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class SignInWithGoogleServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");

    private final FakeUserPersistencePort users = new FakeUserPersistencePort();
    private final FakePersonPersistencePort persons = new FakePersonPersistencePort();
    private final FakeAuditLogPersistencePort audits = new FakeAuditLogPersistencePort();
    private int fetches;

    private final UseCaseFixtures.FakeAccountEventPublisherPort events =
            new UseCaseFixtures.FakeAccountEventPublisherPort();
    private final SignInWithGoogleService service = new SignInWithGoogleService(users, persons,
            new FakePasswordHasherPort(), new FakeTokenGeneratorPort(),
            url -> {
                fetches++;
                return Optional.of("data:image/jpeg;base64,AAAA");
            },
            new FakeIdentifierGeneratorPort(), audits, events, Clock.fixed(NOW, ZoneOffset.UTC));

    private static GoogleIdentity google(String sub, String email, String given, String family) {
        return new GoogleIdentity(sub, email, true, given, family, given == null ? null : given + " X",
                "https://lh3.googleusercontent.com/a/photo=s96-c");
    }

    @Test
    void theFirstSignInCreatesAVerifiedAccountWithTheGoogleData() {
        var signedIn = service.signIn(google("g-1", "ana@gmail.com", "Ana", "Pérez"), "10.0.0.1", true).orElseThrow();

        User user = users.findActive(signedIn.idUser()).orElseThrow();
        assertEquals("ana@gmail.com", user.email().value());
        assertTrue(user.isEmailVerified());
        assertEquals(Optional.of("g-1"), user.googleSubject());
        assertEquals(Optional.of("data:image/jpeg;base64,AAAA"), user.profileImage());
        var person = persons.findActive(user.idPerson()).orElseThrow();
        assertEquals("Ana", person.name());
        assertEquals("Pérez", person.lastName());
        assertEquals(NOW, user.lastLoginAt().orElseThrow());
    }

    @Test
    void aGoogleAccountWithoutLastNameIsAccepted() {
        var signedIn = service.signIn(google("g-2", "luis@gmail.com", "Luis", null), "ip", true).orElseThrow();

        var person = persons.findActive(users.findActive(signedIn.idUser()).orElseThrow().idPerson()).orElseThrow();
        assertEquals("Luis", person.name());
        assertNull(person.lastName());
    }

    @Test
    void withoutAnyNameTheAddressGivesTheFirstName() {
        var signedIn = service.signIn(google("g-3", "mora.c@gmail.com", null, null), "ip", true).orElseThrow();

        var person = persons.findActive(users.findActive(signedIn.idUser()).orElseThrow().idPerson()).orElseThrow();
        assertEquals("mora.c", person.name());
    }

    @Test
    void theNextSignInReusesTheAccountWithoutDownloadingThePhotoAgain() {
        var first = service.signIn(google("g-1", "ana@gmail.com", "Ana", "Pérez"), "ip", true).orElseThrow();
        var second = service.signIn(google("g-1", "ana@gmail.com", "Ana", "Pérez"), "ip", true).orElseThrow();

        assertEquals(first.idUser(), second.idUser());
        assertEquals(1, users.users().size());
        assertEquals(1, fetches);
        assertEquals(1, events.eventsOf(AccountRegistered.class).size(),
                "only the sign-in that creates the account announces it");
    }

    @Test
    void anAccountRegisteredWithAPasswordIsNotTakenOver() {
        users.seed("usr0000001", "per0000001", "ana@gmail.com", UserStatus.ACTIVE);

        assertThrows(EmailAlreadyRegisteredException.class,
                () -> service.signIn(google("g-1", "ana@gmail.com", "Ana", "Pérez"), "ip", true));
        assertEquals(1, users.users().size());
    }

    @Test
    void anAddressGoogleDidNotVerifyIsRefused() {
        var unverified = new GoogleIdentity("g-4", "x@gmail.com", false, "X", null, null, null);

        assertTrue(service.signIn(unverified, "ip", true).isEmpty());
        assertTrue(users.users().isEmpty());
    }

    @Test
    void aBlockedAccountCannotSignIn() {
        var signedIn = service.signIn(google("g-1", "ana@gmail.com", "Ana", "Pérez"), "ip", true).orElseThrow();
        users.findActive(signedIn.idUser()).orElseThrow().block();

        assertThrows(AccountNotActiveException.class,
                () -> service.signIn(google("g-1", "ana@gmail.com", "Ana", "Pérez"), "ip", true));
    }

    @Test
    void creatingTheAccountRequiresAcceptingTheTermsAndCreatesNothingWithout() {
        assertThrows(TermsNotAcceptedException.class,
                () -> service.signIn(google("g-1", "ana@gmail.com", "Ana", "Pérez"), "ip", false));

        assertTrue(users.users().isEmpty());
        assertTrue(events.events().isEmpty());
    }

    @Test
    void theAccountCreatedWithGoogleRecordsWhenItAcceptedTheTerms() {
        var signedIn = service.signIn(google("g-1", "ana@gmail.com", "Ana", "Pérez"), "ip", true).orElseThrow();

        assertEquals(Optional.of(NOW), users.findActive(signedIn.idUser()).orElseThrow().termsAcceptedAt());
    }

    @Test
    void anAccountThatAcceptedTheTermsSignsInWithoutBeingAskedAgain() {
        service.signIn(google("g-1", "ana@gmail.com", "Ana", "Pérez"), "ip", true);

        assertTrue(service.signIn(google("g-1", "ana@gmail.com", "Ana", "Pérez"), "ip", false).isPresent());
    }

    @Test
    void aGoogleAccountCreatedBeforeTheTermsWereRequiredAcceptsThemAtItsNextSignIn() {
        User old = User.register("use0000077", "per0000077", PasswordHash.of("hash:x"),
                Email.of("ana@gmail.com"), NOW.minusSeconds(86_400), null);
        old.verifyEmail();
        old.bindGoogleAccount("g-1");
        users.save(old);

        assertThrows(TermsNotAcceptedException.class,
                () -> service.signIn(google("g-1", "ana@gmail.com", "Ana", "Pérez"), "ip", false));
        assertTrue(service.signIn(google("g-1", "ana@gmail.com", "Ana", "Pérez"), "ip", true).isPresent());
        assertEquals(Optional.of(NOW), users.findActive("use0000077").orElseThrow().termsAcceptedAt());
    }
}
