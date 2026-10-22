package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.UpdateUserProfileCommand;
import com.energymonitor.security.application.exception.EmailAlreadyRegisteredException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.UpdateUserProfile;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.PersonPersistencePort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.Person;
import com.energymonitor.security.domain.model.User;
import java.time.Clock;
import java.time.Instant;

/**
 * Edits the personal data of a user and, optionally, the account email and avatar.
 *
 * <p>The split follows ownership: name and last name belong to {@code person}, while the email and
 * the profile image belong to {@code user}. No residential address is edited here, because that
 * value is the {@code home} module's to own, and no phone number either, since notifications are
 * email only.
 */
public class UpdateUserProfileService implements UpdateUserProfile {

    private final UserPersistencePort userPort;
    private final PersonPersistencePort personPort;
    private final AuditLogPersistencePort auditLogPort;
    private final IdentifierGeneratorPort identifiers;
    private final Clock clock;

    public UpdateUserProfileService(UserPersistencePort userPort, PersonPersistencePort personPort,
                                    AuditLogPersistencePort auditLogPort,
                                    IdentifierGeneratorPort identifiers, Clock clock) {
        this.userPort = userPort;
        this.personPort = personPort;
        this.auditLogPort = auditLogPort;
        this.identifiers = identifiers;
        this.clock = clock;
    }

    @Override
    public Person update(UpdateUserProfileCommand command) {
        Instant now = clock.instant();
        User user = userPort.findActive(command.idUser())
                .orElseThrow(() -> new UserNotFoundException("no active user " + command.idUser()));
        Person person = personPort.findActive(user.idPerson())
                .orElseThrow(() -> new UserNotFoundException("no active person " + user.idPerson()));

        // Saved once, after every personal attribute has been applied. Saving inside each branch
        // would persist the person when only one field changed, and skip it entirely when the
        // other did, which is how a rename used to be lost.
        boolean personChanged = false;
        if (command.name() != null && command.lastName() != null) {
            person.rename(command.name(), command.lastName());
            personChanged = true;
        }
        if (personChanged) {
            personPort.save(person);
        }

        // The avatar is account state, so it changes on the User and not on the Person.
        boolean accountChanged = false;
        if (command.newEmail() != null) {
            Email newEmail = Email.of(command.newEmail());
            userPort.findActiveByEmail(newEmail).ifPresent(existing -> {
                if (!existing.equals(user)) {
                    throw new EmailAlreadyRegisteredException("an account already exists for " + newEmail);
                }
            });
            user.changeEmail(newEmail);
            accountChanged = true;
        }
        if (command.profileImage() != null) {
            user.changeProfileImage(command.profileImage().isBlank() ? null : command.profileImage());
            accountChanged = true;
        }
        // Saved once, after every account attribute has been applied. Saving inside each branch
        // would persist the account when only the address changed was intended, and skip it
        // entirely when only the avatar was, which is how an avatar change used to be lost.
        if (accountChanged) {
            userPort.save(user);
        }

        auditLogPort.save(new AuditLog(identifiers.generate(), user.idUser(), AuditAction.UPDATE,
                null, command.ipAddress(), null, now));
        return person;
    }
}