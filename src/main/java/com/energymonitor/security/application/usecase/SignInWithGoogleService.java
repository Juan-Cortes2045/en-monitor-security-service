package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.exception.AccountNotActiveException;
import com.energymonitor.security.application.exception.EmailAlreadyRegisteredException;
import com.energymonitor.security.application.exception.TermsNotAcceptedException;
import com.energymonitor.security.application.port.in.SignInWithGoogle;
import com.energymonitor.security.api.AccountFirstSignedIn;
import com.energymonitor.security.api.AccountRegistered;
import com.energymonitor.security.application.port.out.AccountEventPublisherPort;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.PasswordHasherPort;
import com.energymonitor.security.application.port.out.PersonPersistencePort;
import com.energymonitor.security.application.port.out.ProfileImageFetcherPort;
import com.energymonitor.security.application.port.out.TokenGeneratorPort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.application.result.AuthenticatedUser;
import com.energymonitor.security.application.result.GoogleIdentity;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.Person;
import com.energymonitor.security.domain.model.User;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * Signs in with Google, creating the account the first time.
 *
 * <ul>
 *   <li>The Google account is recognised by its {@code sub}, not by its address: the address of
 *       a Google account can change, its {@code sub} cannot.</li>
 *   <li>An address Google did not verify is refused.</li>
 *   <li>An address that already belongs to an account registered with a password is refused
 *       (409): signing in with Google never takes over an existing account.</li>
 *   <li>A new account takes the first name, the last name (when Google has one), the photo and
 *       the address from Google, starts verified, and gets a random password nobody knows: every
 *       password flow keeps working, and "forgot password" lets the person set one.</li>
 * </ul>
 *
 * <p>This service contains no Spring annotations; the wiring makes it transactional.
 */
public class SignInWithGoogleService implements SignInWithGoogle {

    private static final int NAME_MAX = 100;

    private final UserPersistencePort users;
    private final PersonPersistencePort persons;
    private final PasswordHasherPort passwordHasher;
    private final TokenGeneratorPort tokens;
    private final ProfileImageFetcherPort images;
    private final IdentifierGeneratorPort identifiers;
    private final AuditLogPersistencePort audits;
    private final AccountEventPublisherPort events;
    private final Clock clock;

    public SignInWithGoogleService(UserPersistencePort users, PersonPersistencePort persons,
                                   PasswordHasherPort passwordHasher, TokenGeneratorPort tokens,
                                   ProfileImageFetcherPort images, IdentifierGeneratorPort identifiers,
                                   AuditLogPersistencePort audits,
                                   AccountEventPublisherPort events, Clock clock) {
        this.users = users;
        this.persons = persons;
        this.passwordHasher = passwordHasher;
        this.tokens = tokens;
        this.images = images;
        this.identifiers = identifiers;
        this.audits = audits;
        this.events = events;
        this.clock = clock;
    }

    @Override
    public Optional<AuthenticatedUser> signIn(GoogleIdentity identity, String ipAddress,
                                              boolean acceptTerms) {
        if (!identity.emailVerified() || identity.email() == null || identity.subject() == null) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        Email email = Email.of(identity.email());

        User user = users.findActiveByGoogleSubject(identity.subject()).orElse(null);
        if (user == null) {
            if (users.findActiveByEmail(email).isPresent()) {
                throw new EmailAlreadyRegisteredException(
                        "an account already exists for " + email + "; sign in with its password");
            }
            // Signing up with Google skips the registration form and its checkbox: the terms are
            // asked here, before anything is created.
            requireTerms(acceptTerms);
            user = create(identity, email, ipAddress, now);
        }
        if (!user.canAuthenticate()) {
            throw new AccountNotActiveException("account is " + user.status());
        }
        // Accounts created with Google before the terms were required accept them now.
        if (!user.hasAcceptedTerms()) {
            requireTerms(acceptTerms);
            user.acceptTerms(now);
        }
        boolean firstSignIn = user.lastLoginAt().isEmpty();
        user.recordSuccessfulLogin(now);
        users.save(user);
        audits.save(AuditLog.login(identifiers.generate(), user, ipAddress, now));
        if (firstSignIn) {
            events.accountFirstSignedIn(new AccountFirstSignedIn(user.idUser(), now));
        }
        return Optional.of(new AuthenticatedUser(user.idUser(), user.idPerson(), user.email(),
                user.status(), user.lastLoginAt().orElseThrow(), user.profileImage().orElse(null)));
    }

    private User create(GoogleIdentity identity, Email email, String ipAddress, Instant now) {
        Person person = new Person(identifiers.generate(), firstName(identity, email),
                trimmed(identity.familyName()));
        persons.save(person);

        String photo = identity.pictureUrl() == null ? null
                : images.fetchAsDataUrl(identity.pictureUrl()).orElse(null);
        // Nobody knows this password: the account signs in with Google until its owner sets one
        // through "forgot password".
        User user = User.register(identifiers.generate(), person.idPerson(),
                passwordHasher.hash(tokens.generateToken()), email, now, photo);
        user.verifyEmail();
        user.bindGoogleAccount(identity.subject());
        users.save(user);
        audits.save(new AuditLog(identifiers.generate(), user.idUser(), AuditAction.CREATE, null,
                ipAddress, null, now));
        events.accountRegistered(new AccountRegistered(user.idUser(), email.value(), now));
        return user;
    }

    private static void requireTerms(boolean acceptTerms) {
        if (!acceptTerms) {
            throw new TermsNotAcceptedException("Accept the terms and conditions to continue with Google.");
        }
    }

    /** Given name, else the display name, else the part of the address before the @. */
    private static String firstName(GoogleIdentity identity, Email email) {
        String name = trimmed(identity.givenName());
        if (name == null) {
            name = trimmed(identity.fullName());
        }
        if (name == null) {
            name = email.value().substring(0, email.value().indexOf('@'));
        }
        return name.length() > NAME_MAX ? name.substring(0, NAME_MAX) : name;
    }

    private static String trimmed(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String t = value.trim();
        return t.length() > NAME_MAX ? t.substring(0, NAME_MAX) : t;
    }
}
