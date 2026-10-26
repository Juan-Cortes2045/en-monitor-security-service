package com.energymonitor.security.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * A registration waiting for its email address to be confirmed. No {@link User} and no
 * {@link Person} exist until the verification code comes back.
 *
 * <p>Registering used to create the account straight away, unverified. An address that looked
 * deliverable but had no mailbox behind it left an account nobody could ever verify, holding its
 * address forever. Now only this request is kept, for {@link #LIFETIME}, and it is removed either
 * when it becomes an account or when it expires.
 *
 * <p>{@link #idUser()} is reserved here: the account takes it when it is created, so the
 * verification code, which is derived from it, and the delivery record of the mail already point
 * at the account it becomes.
 *
 * <p>Maps to the {@code pending_registration} table.
 */
public final class PendingRegistration {

    /** How long a registration waits for its code before it is forgotten. */
    public static final Duration LIFETIME = Duration.ofHours(24);

    private static final int ID_MAX = 10;
    private static final int NAME_MAX = 100;
    private static final int PROFILE_IMAGE_MAX = 500_000;
    private static final int IP_ADDRESS_MAX = 45;

    private final String idUser;
    private final Email email;
    private final String name;
    private final String lastName;
    private final PasswordHash passwordHash;
    private final String profileImage;
    private final String ipAddress;
    private final Instant requestedAt;
    private final Instant expiresAt;

    /** Rehydrates a stored request; {@link #request} is how a new one is made. */
    public PendingRegistration(String idUser, Email email, String name, String lastName,
                               PasswordHash passwordHash, String profileImage, String ipAddress,
                               Instant requestedAt, Instant expiresAt) {
        this.idUser = Preconditions.text(idUser, ID_MAX, "idUser");
        this.email = Preconditions.notNull(email, "email");
        this.name = Preconditions.text(name, NAME_MAX, "name");
        this.lastName = Preconditions.optionalText(lastName, NAME_MAX, "lastName");
        this.passwordHash = Preconditions.notNull(passwordHash, "passwordHash");
        this.profileImage = Preconditions.optionalText(profileImage, PROFILE_IMAGE_MAX, "profileImage");
        this.ipAddress = Preconditions.optionalText(ipAddress, IP_ADDRESS_MAX, "ipAddress");
        this.requestedAt = Preconditions.notNull(requestedAt, "requestedAt");
        this.expiresAt = Preconditions.notNull(expiresAt, "expiresAt");
        Preconditions.expirationAfter(requestedAt, expiresAt);
    }

    /**
     * @param idUser       the identifier the account will take
     * @param ipAddress    the caller's address, recorded in the audit trail when the account is
     *                     created
     * @param requestedAt  now; the request expires {@link #LIFETIME} later
     */
    public static PendingRegistration request(String idUser, Email email, String name,
                                              String lastName, PasswordHash passwordHash,
                                              String profileImage, String ipAddress,
                                              Instant requestedAt) {
        return new PendingRegistration(idUser, email, name, lastName, passwordHash, profileImage,
                ipAddress, requestedAt, requestedAt.plus(LIFETIME));
    }

    /** @return whether the request can no longer become an account */
    public boolean isExpiredAt(Instant instant) {
        return !instant.isBefore(expiresAt);
    }

    /** @return the person of the account, with a fresh identifier */
    public Person toPerson(String idPerson) {
        return new Person(idPerson, name, lastName);
    }

    /**
     * @return the account, active, with its address already verified and the terms accepted when
     *         the request was made (registering requires accepting them)
     */
    public User toUser(Person person, Instant createdAt) {
        User user = User.register(idUser, person.idPerson(), passwordHash, email, createdAt,
                profileImage);
        user.verifyEmail();
        user.acceptTerms(requestedAt);
        return user;
    }

    public String idUser() {
        return idUser;
    }

    public Email email() {
        return email;
    }

    public String name() {
        return name;
    }

    public Optional<String> lastName() {
        return Optional.ofNullable(lastName);
    }

    public PasswordHash passwordHash() {
        return passwordHash;
    }

    public Optional<String> profileImage() {
        return Optional.ofNullable(profileImage);
    }

    public Optional<String> ipAddress() {
        return Optional.ofNullable(ipAddress);
    }

    public Instant requestedAt() {
        return requestedAt;
    }

    public Instant expiresAt() {
        return expiresAt;
    }
}
