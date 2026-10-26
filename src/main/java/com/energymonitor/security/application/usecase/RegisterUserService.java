package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.RegisterUserCommand;
import com.energymonitor.security.application.exception.EmailAlreadyRegisteredException;
import com.energymonitor.security.application.exception.PasswordPolicyViolationException;
import com.energymonitor.security.application.port.in.RegisterUser;
import com.energymonitor.security.application.port.out.EmailDomainCheckPort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.PasswordHasherPort;
import com.energymonitor.security.application.port.out.PasswordPolicyPersistencePort;
import com.energymonitor.security.application.port.out.PendingRegistrationPersistencePort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordPolicy;
import com.energymonitor.security.domain.model.PendingRegistration;
import java.time.Clock;

/**
 * Asks for a new account: validates the request and keeps it until its address is verified.
 *
 * <p>No {@code person} nor {@code user} row is written here. They are created by
 * {@link EmailVerificationService} when the code sent to the address comes back, so an address
 * nobody reads never becomes an account. Registering again with the same address replaces the
 * earlier request (a mistyped password can be fixed that way) and invalidates its code, which is
 * derived from the identifier the request reserves.
 */
public class RegisterUserService implements RegisterUser {

    private final UserPersistencePort userPort;
    private final PendingRegistrationPersistencePort pendingPort;
    private final PasswordPolicyPersistencePort passwordPolicyPort;
    private final PasswordHasherPort passwordHasher;
    private final IdentifierGeneratorPort identifiers;
    private final EmailDomainCheckPort emailDomains;
    private final Clock clock;

    public RegisterUserService(UserPersistencePort userPort,
                               PendingRegistrationPersistencePort pendingPort,
                               PasswordPolicyPersistencePort passwordPolicyPort,
                               PasswordHasherPort passwordHasher,
                               IdentifierGeneratorPort identifiers,
                               EmailDomainCheckPort emailDomains, Clock clock) {
        this.userPort = userPort;
        this.pendingPort = pendingPort;
        this.passwordPolicyPort = passwordPolicyPort;
        this.passwordHasher = passwordHasher;
        this.identifiers = identifiers;
        this.emailDomains = emailDomains;
        this.clock = clock;
    }

    @Override
    public PendingRegistration register(RegisterUserCommand command) {
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
        // anything is stored. Whether the mailbox itself exists is what the code then proves.
        DeliverableEmail.require(email, emailDomains);

        return pendingPort.save(PendingRegistration.request(identifiers.generate(), email,
                command.name(), command.lastName(), passwordHasher.hash(command.rawPassword()),
                command.profileImage(), command.ipAddress(), clock.instant()));
    }
}
