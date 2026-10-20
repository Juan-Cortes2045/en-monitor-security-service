package com.energymonitor.security.adapter.out.persistence.entity;

import com.energymonitor.security.domain.model.UserStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * JPA mapping of the {@code user} table.
 *
 * <p>{@code person_id} is mapped as a plain identifier column rather than a
 * {@code @ManyToOne}. The relationship exists in the schema and MySQL enforces it with
 * {@code fk_user_person_id}, but nothing in this phase needs to walk from a user to its
 * person object, and a unidirectional association would only add a lazy proxy to load
 * without being read. The same reasoning applies to every other Security foreign key.
 *
 * <p>{@code password_hash} and {@code email} are stored as text here. The domain wraps them
 * in {@code PasswordHash} and {@code Email} value objects; that conversion belongs to the
 * mapper, not to the mapping.
 */
@Entity
@Table(name = "user")
public class UserEntity extends BaseAuditEntity {

    @Id
    @Column(name = "id_user", nullable = false, length = 10)
    private String idUser;

    @Column(name = "person_id", nullable = false, length = 10)
    private String personId;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "email", nullable = false, length = 255)
    private String email;

    @Column(name = "email_verified", nullable = false)
    @TinyIntBoolean
    private boolean emailVerified;

    @Column(name = "registration_date", nullable = false)
    private Instant registrationDate;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private UserStatus status;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @Column(name = "profile_image", columnDefinition = "MEDIUMTEXT")
    private String profileImage;

    @Column(name = "google_subject", length = 255)
    private String googleSubject;

    public UserEntity() {
    }

    public String getIdUser() {
        return idUser;
    }

    public void setIdUser(String idUser) {
        this.idUser = idUser;
    }

    public String getPersonId() {
        return personId;
    }

    public void setPersonId(String personId) {
        this.personId = personId;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public Instant getRegistrationDate() {
        return registrationDate;
    }

    public void setRegistrationDate(Instant registrationDate) {
        this.registrationDate = registrationDate;
    }

    public UserStatus getStatus() {
        return status;
    }

    public void setStatus(UserStatus status) {
        this.status = status;
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public void setFailedLoginAttempts(int failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    public Instant getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(Instant lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    public String getGoogleSubject() {
        return googleSubject;
    }

    public void setGoogleSubject(String googleSubject) {
        this.googleSubject = googleSubject;
    }

    public String getProfileImage() {
        return profileImage;
    }

    public void setProfileImage(String profileImage) {
        this.profileImage = profileImage;
    }
}
