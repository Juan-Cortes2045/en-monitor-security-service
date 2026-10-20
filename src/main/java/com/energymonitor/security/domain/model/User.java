package com.energymonitor.security.domain.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * System account associated with a {@link Person}. Aggregate root of the account lifecycle.
 *
 * <p>Owns credentials, account state and login history. It references the person by identifier
 * only: personal data is not part of this aggregate (INV-002), and the one-to-one link is
 * enforced by {@code uk_user_person_id}.
 *
 * <p>Maps to the {@code user} table.
 */
public class User {

    /** Room for a 256 px avatar as a data URL; the column is MEDIUMTEXT. */
    private static final int PROFILE_IMAGE_MAX = 500_000;

    private final String idUser;
    private final String idPerson;
    private PasswordHash passwordHash;
    private Email email;
    private boolean emailVerified;
    private final Instant dateOfRegistration;
    private UserStatus status;
    private int failedLoginAttempts;
    private Instant lastLoginAt;
    private String profileImage;
    private String googleSubject;

    /**
     * Rehydrates or registers an account. Prefer {@link #register} for new accounts.
     *
     * @param idUser               identifier, {@code VARCHAR(10)}
     * @param idPerson             identifier of the owning person
     * @param passwordHash         already-hashed password, never plain text (INV-004)
     * @param email                account address
     * @param emailVerified        whether the address has been confirmed
     * @param dateOfRegistration   when the account was registered
     * @param status               initial state
     * @param failedLoginAttempts  consecutive failures, not negative
     * @param lastLoginAt          last successful login, may be {@code null}
     */
    public User(String idUser, String idPerson, PasswordHash passwordHash, Email email,
                boolean emailVerified, Instant dateOfRegistration, UserStatus status,
                int failedLoginAttempts, Instant lastLoginAt, String profileImage) {
        this.idUser = Preconditions.text(idUser, "idUser");
        this.idPerson = Preconditions.text(idPerson, "idPerson");
        this.passwordHash = Preconditions.notNull(passwordHash, "passwordHash");
        this.email = Preconditions.notNull(email, "email");
        this.emailVerified = emailVerified;
        this.dateOfRegistration = Preconditions.notNull(dateOfRegistration, "dateOfRegistration");
        this.status = Preconditions.notNull(status, "status");
        this.failedLoginAttempts = Preconditions.notNegative(failedLoginAttempts, "failedLoginAttempts");
        this.lastLoginAt = lastLoginAt;
        this.profileImage = Preconditions.optionalText(profileImage, PROFILE_IMAGE_MAX, "profileImage");
    }

    /**
     * Registers a new account. The hash is expected to already be computed by the security
     * adapter; the domain does not hash (INV-004).
     *
     * @param idUser             identifier
     * @param idPerson           identifier of the owning person
     * @param passwordHash       already-hashed password
     * @param email              account address
     * @param dateOfRegistration registration instant
     * @param profileImage       optional avatar shown for the account
     * @return a new active account with no failed attempts
     */
    public static User register(String idUser, String idPerson, PasswordHash passwordHash,
                                Email email, Instant dateOfRegistration, String profileImage) {
        return new User(idUser, idPerson, passwordHash, email, false, dateOfRegistration,
                UserStatus.ACTIVE, 0, null, profileImage);
    }

    /** @return the identifier */
    public String idUser() {
        return idUser;
    }

    /** @return identifier of the owning person */
    public String idPerson() {
        return idPerson;
    }

    /**
     * Exposes the hash for the security adapter only.
     *
     * @return the stored password hash
     */
    public PasswordHash passwordHash() {
        return passwordHash;
    }

    /** @return the account address */
    public Email email() {
        return email;
    }

    /** @return whether the email has been confirmed */
    public boolean isEmailVerified() {
        return emailVerified;
    }

    /** @return registration instant */
    public Instant dateOfRegistration() {
        return dateOfRegistration;
    }

    /** @return current account state */
    public UserStatus status() {
        return status;
    }

    /** @return consecutive failed login attempts */
    public int failedLoginAttempts() {
        return failedLoginAttempts;
    }

    /** @return last successful login, empty when the account never logged in */
    public Optional<Instant> lastLoginAt() {
        return Optional.ofNullable(lastLoginAt);
    }

    /**
     * Whether this account may authenticate.
     *
     * <p>Only {@link UserStatus#ACTIVE} may. A blocked account must never authenticate
     * (INV-005).
     *
     * @return {@code true} when the account is active
     */
    public boolean canAuthenticate() {
        return status.allowsAuthentication();
    }

    /** Replaces the password hash, e.g. after a reset. */
    public void changePassword(PasswordHash newHash) {
        this.passwordHash = Preconditions.notNull(newHash, "passwordHash");
    }

    /** @return profile image URL or path, empty when not provided */
    /**
     * The Google account ({@code sub} of its ID token) this account was created with, when it
     * was created by signing in with Google. Accounts registered with a password have none and
     * are never taken over by a Google sign-in with the same address.
     */
    public Optional<String> googleSubject() {
        return Optional.ofNullable(googleSubject);
    }

    /** Binds the account to a Google account; done once, when it is created from Google. */
    public void bindGoogleAccount(String subject) {
        this.googleSubject = Preconditions.optionalText(subject, 255, "googleSubject");
    }

    public Optional<String> profileImage() {
        return Optional.ofNullable(profileImage);
    }

    /**
     * Replaces the avatar shown for this account.
     *
     * <p>The image is an attribute of the account rather than of the person behind it, which is
     * why it lives here and not on {@link Person}. Passing {@code null} clears it.
     *
     * @param profileImage new image location or {@code null}
     */
    public void changeProfileImage(String profileImage) {
        this.profileImage = Preconditions.optionalText(profileImage, PROFILE_IMAGE_MAX, "profileImage");
    }

    /** Replaces the account address. Uniqueness is checked by the persistence layer (INV-003). */
    public void changeEmail(Email newEmail) {
        this.email = Preconditions.notNull(newEmail, "email");
        this.emailVerified = false;
    }

    /** Marks the address as confirmed. */
    public void verifyEmail() {
        this.emailVerified = true;
    }

    /** Moves the account to {@link UserStatus#ACTIVE}, clearing the failure counter. */
    public void activate() {
        this.status = UserStatus.ACTIVE;
        this.failedLoginAttempts = 0;
    }

    /** Moves the account to {@link UserStatus#INACTIVE}. */
    public void deactivate() {
        this.status = UserStatus.INACTIVE;
    }

    /** Moves the account to {@link UserStatus#BLOCKED} (INV-005). */
    public void block() {
        this.status = UserStatus.BLOCKED;
    }

    /** Records one more failed authentication attempt. The counter never goes negative. */
    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts = Preconditions.notNegative(failedLoginAttempts + 1, "failedLoginAttempts");
    }

    /** Clears the failure counter after a successful authentication. */
    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
    }

    /**
     * Records a successful authentication: stamps the login instant and clears the counter.
     *
     * <p>Refuses to record a login for an account that cannot authenticate, so a blocked
     * account can never present itself as having logged in (INV-005).
     *
     * @param instant when the login happened
     * @throws IllegalStateException if the account is not active
     */
    public void recordSuccessfulLogin(Instant instant) {
        Preconditions.notNull(instant, "instant");
        if (!canAuthenticate()) {
            throw new IllegalStateException("account is " + status + " and cannot authenticate");
        }
        this.lastLoginAt = instant;
        this.failedLoginAttempts = 0;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof User user)) {
            return false;
        }
        return idUser.equals(user.idUser);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idUser);
    }

    @Override
    public String toString() {
        return "User{idUser='" + idUser + "', email=" + email + ", status=" + status + "}";
    }
}
