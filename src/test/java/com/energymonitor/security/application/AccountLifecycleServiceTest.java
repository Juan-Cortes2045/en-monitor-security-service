package com.energymonitor.security.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.command.ChangeUserStatusCommand;
import com.energymonitor.security.application.command.UpdateUserProfileCommand;
import com.energymonitor.security.application.exception.EmailAlreadyRegisteredException;
import com.energymonitor.security.application.usecase.FindUserService;
import com.energymonitor.security.application.usecase.ManageUserStatusService;
import com.energymonitor.security.application.usecase.UpdateUserProfileService;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.Person;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * {@code FindUser}, {@code UpdateUserProfile} and {@code ManageUserStatus}: the read path, the
 * profile edit path and the account-state switch.
 */
class AccountLifecycleServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-03-01T12:00:00Z"), ZoneOffset.UTC);

    private final UseCaseFixtures.FakeUserPersistencePort users = new UseCaseFixtures.FakeUserPersistencePort();
    private final UseCaseFixtures.FakePersonPersistencePort persons = new UseCaseFixtures.FakePersonPersistencePort();
    private final UseCaseFixtures.FakeAuditLogPersistencePort audits = new UseCaseFixtures.FakeAuditLogPersistencePort();
    private final UseCaseFixtures.FakeIdentifierGeneratorPort identifiers =
            new UseCaseFixtures.FakeIdentifierGeneratorPort();
    private final FindUserService findUser = new FindUserService(users);
    private final UpdateUserProfileService updateProfile =
            new UpdateUserProfileService(users, persons, audits, identifiers, CLOCK);
    private final ManageUserStatusService manageStatus =
            new ManageUserStatusService(users, audits, identifiers, CLOCK);

    private void seedAda() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);
        persons.seed("per0000001");
    }

    @Test
    void findsUserByIdentifierAndByNormalisedEmail() {
        seedAda();

        assertEquals("use0000001", findUser.findByIdentifier("use0000001").orElseThrow().idUser());
        assertEquals("use0000001", findUser.findByEmail("ADA@example.com").orElseThrow().idUser());
        assertTrue(findUser.findByIdentifier("ghost").isEmpty());
    }

    @Test
    void updatesThePersonalDataOfThePerson() {
        seedAda();

        Person updated = updateProfile.update(new UpdateUserProfileCommand("use0000001",
                "Grace", "Hopper", null, null, "10.0.0.5"));

        assertEquals("Grace", persons.findActive(updated.idPerson()).orElseThrow().name());
        assertEquals("Hopper", updated.lastName());
        assertEquals(AuditAction.UPDATE, audits.logs().getFirst().action());
    }

    @Test
    void writesTheRenameThroughThePersonPort() {
        // Reading the person back is not proof on its own: the fake hands back the very instance
        // the use case mutated, so a rename that was never saved would still look applied. Only
        // the recorded save proves the row was written, and it also shows what it was written
        // with, which is the pair the endpoint's response is built from.
        seedAda();
        assertTrue(persons.savedNames().isEmpty(), "The fixture started with an unsaved person");

        updateProfile.update(new UpdateUserProfileCommand("use0000001",
                "Grace", "Hopper", null, null, "10.0.0.5"));

        assertEquals(List.of("Grace Hopper"), persons.savedNames());
    }

    @Test
    void writesNoPersonWhenTheRequestCarriesNoName() {
        // An avatar-only or email-only edit must not touch the person: absent means unchanged,
        // so writing the row here would be the only way the name could be lost.
        seedAda();

        updateProfile.update(new UpdateUserProfileCommand("use0000001",
                null, null, "https://cdn.example.com/grace.png", null, "10.0.0.5"));

        assertTrue(persons.savedNames().isEmpty(),
                "A profile edit with no name wrote to the person anyway");
        assertEquals("Ada", persons.findActive("per0000001").orElseThrow().name());
    }

    @Test
    void theAvatarIsPersistedOnTheAccountNotOnThePerson() {
        seedAda();

        updateProfile.update(new UpdateUserProfileCommand("use0000001",
                null, null, "https://cdn.example.com/grace.png", null, "10.0.0.5"));

        // The avatar is account state. Losing it because only the person was saved is exactly
        // the failure this assertion guards.
        assertEquals("https://cdn.example.com/grace.png",
                users.findActive("use0000001").orElseThrow().profileImage().orElseThrow());
    }

    @Test
    void aBlankAvatarRemovesTheImageAndAbsentKeepsIt() {
        seedAda();
        updateProfile.update(new UpdateUserProfileCommand("use0000001",
                null, null, "data:image/jpeg;base64," + "A".repeat(30_000), null, "10.0.0.5"));
        assertTrue(users.findActive("use0000001").orElseThrow().profileImage().isPresent());

        updateProfile.update(new UpdateUserProfileCommand("use0000001",
                null, null, null, null, "10.0.0.5"));
        assertTrue(users.findActive("use0000001").orElseThrow().profileImage().isPresent());

        updateProfile.update(new UpdateUserProfileCommand("use0000001",
                null, null, "", null, "10.0.0.5"));
        assertTrue(users.findActive("use0000001").orElseThrow().profileImage().isEmpty());
    }

    @Test
    void changesTheAccountEmailAndResetsVerification() {
        seedAda();

        updateProfile.update(new UpdateUserProfileCommand("use0000001",
                null, null, null, "grace@example.com", null));

        assertEquals("grace@example.com", users.findActive("use0000001").orElseThrow().email().value());
        assertFalse(users.findActive("use0000001").orElseThrow().isEmailVerified());
    }

    @Test
    void rejectsTransferringAnEmailAlreadyInUse() {
        seedAda();
        users.seed("use0000002", "per0000002", "taken@example.com", UserStatus.ACTIVE);

        assertThrows(EmailAlreadyRegisteredException.class,
                () -> updateProfile.update(new UpdateUserProfileCommand("use0000001",
                        null, null, null, "taken@example.com", null)));
    }

    @Test
    void movesBetweenEveryAccountStatus() {
        seedAda();

        manageStatus.changeStatus(new ChangeUserStatusCommand("use0000001", UserStatus.BLOCKED, null));
        assertEquals(UserStatus.BLOCKED, users.findActive("use0000001").orElseThrow().status());

        manageStatus.changeStatus(new ChangeUserStatusCommand("use0000001", UserStatus.ACTIVE, null));
        assertEquals(UserStatus.ACTIVE, users.findActive("use0000001").orElseThrow().status());

        manageStatus.changeStatus(new ChangeUserStatusCommand("use0000001", UserStatus.INACTIVE, null));
        assertEquals(UserStatus.INACTIVE, users.findActive("use0000001").orElseThrow().status());
    }
}