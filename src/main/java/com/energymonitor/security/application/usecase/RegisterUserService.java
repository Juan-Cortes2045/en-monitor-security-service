package com.energymonitor.security.application.usecase;

import com.energymonitor.security.api.AccountRegistered;
import com.energymonitor.security.application.command.RegisterUserCommand;
import com.energymonitor.security.application.exception.EmailAlreadyRegisteredException;
import com.energymonitor.security.application.exception.PasswordPolicyViolationException;
import com.energymonitor.security.application.exception.UndeliverableEmailException;
import com.energymonitor.security.application.port.in.RegisterUser;
import com.energymonitor.security.application.port.out.AccountEventPublisherPort;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.EmailDomainCheckPort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.PasswordHasherPort;
import com.energymonitor.security.application.port.out.PasswordPolicyPersistencePort;
import com.energymonitor.security.application.port.out.PersonPersistencePort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordPolicy;
import com.energymonitor.security.domain.model.Person;
import com.energymonitor.security.domain.model.User;
import java.time.Clock;
import java.time.Instant;

/**
 * Registers a {@code Person} and its {@code User} account.
 */
public class RegisterUserService implements RegisterUser {

    private final UserPersistencePort userPort;
    private final PersonPersistencePort personPort;
    private final PasswordPolicyPersistencePort passwordPolicyPort;
    private final PasswordHasherPort passwordHasher;
    private final IdentifierGeneratorPort identifiers;
    private final AuditLogPersistencePort auditLogPort;
    private final AccountEventPublisherPort events;
    private final EmailDomainCheckPort emailDomains;
    private final Clock clock;

    public RegisterUserService(UserPersistencePort userPort, PersonPersistencePort personPort,
                               PasswordPolicyPersistencePort passwordPolicyPort,
                               PasswordHasherPort passwordHasher,
                               IdentifierGeneratorPort identifiers,
                               AuditLogPersistencePort auditLogPort,
                               AccountEventPublisherPort events,
                               EmailDomainCheckPort emailDomains, Clock clock) {
        this.userPort = userPort;
        this.personPort = personPort;
        this.passwordPolicyPort = passwordPolicyPort;
        this.passwordHasher = passwordHasher;
        this.identifiers = identifiers;
        this.auditLogPort = auditLogPort;
        this.events = events;
        this.emailDomains = emailDomains;
        this.clock = clock;
    }

    @Override
    public User register(RegisterUserCommand command) {
        Instant now = clock.instant();
        Email email = Email.of(command.email());
        PasswordPolicy policy = passwordPolicyPort.activePolicy()
                .orElseThrow(() -> new IllegalStateException("no active password policy is configured"));
        if (!policy.isSatisfiedBy(command.rawPassword())) {
            throw new PasswordPolicyViolationException("password does not satisfy the configured policy");
        }
        if (userPort.findActiveByEmail(email).isPresent()) {
            throw new EmailAlreadyRegisteredException("an account already exists for " + email);
        }
        // An invented or mistyped domain can never receive the verification code: refused before
        // anything is created. Whether the mailbox itself exists is what the code then proves.
        if (!emailDomains.acceptsMail(email.domain())) {
            throw new UndeliverableEmailException("The domain of the email address does not exist "
                    + "or cannot receive mail.");
        }

        Person person = new Person(identifiers.generate(), command.name(), command.lastName());
        personPort.save(person);

        // The avatar belongs to the account, not to the person: person only describes the human.
        User user = User.register(identifiers.generate(), person.idPerson(),
                passwordHasher.hash(command.rawPassword()), email, now,
                command.profileImage());
        userPort.save(user);

        auditLogPort.save(new AuditLog(identifiers.generate(), user.idUser(), AuditAction.CREATE,
                null, command.ipAddress(), null, now));
        events.accountRegistered(new AccountRegistered(user.idUser(), email.value(), now));
        return user;
    }
}