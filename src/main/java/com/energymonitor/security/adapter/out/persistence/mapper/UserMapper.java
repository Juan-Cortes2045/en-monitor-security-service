package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.UserEntity;
import com.energymonitor.security.adapter.out.persistence.support.Instants;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordHash;
import com.energymonitor.security.domain.model.User;
import org.springframework.stereotype.Component;

/**
 * Converts {@link User} to and from {@link UserEntity}.
 *
 * <p>This is where the two value objects are unwrapped and rebuilt. The domain keeps
 * {@link Email} and {@link PasswordHash} validated and normalised; the row keeps plain text.
 * The hash is read back through {@code value()} only because the security adapter has to
 * compare it, and the entity never exposes the domain object itself.
 *
 * <p>Rebuilding goes through {@code Email.of} and {@code PasswordHash.of}, so a row that
 * violates a domain invariant fails loudly here instead of producing a half-valid account.
 */
@Component
public class UserMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param user the domain object
     * @return a detached entity ready to be persisted
     */
    public UserEntity toEntity(User user) {
        UserEntity entity = new UserEntity();
        applyTo(entity, user);
        return entity;
    }

    /**
     * Copies the domain state onto an already managed entity, for updates.
     *
     * <p>On update the entity keeps its own {@code id_user}: the identifier is the row's
     * identity and never changes, whereas the domain object may carry a different one only
     * in the impossible case of a rename, which the schema does not support anyway.
     *
     * @param entity the managed entity
     * @param user   the domain object holding the new state
     */
    public void applyTo(UserEntity entity, User user) {
        entity.setIdUser(user.idUser());
        entity.setPersonId(user.idPerson());
        entity.setPasswordHash(user.passwordHash().value());
        entity.setEmail(user.email().value());
        entity.setEmailVerified(user.isEmailVerified());
        entity.setRegistrationDate(Instants.truncate(user.dateOfRegistration()));
        entity.setStatus(user.status());
        entity.setFailedLoginAttempts(user.failedLoginAttempts());
        entity.setLastLoginAt(Instants.truncate(user.lastLoginAt().orElse(null)));
        entity.setProfileImage(user.profileImage().orElse(null));
        entity.setGoogleSubject(user.googleSubject().orElse(null));
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public User toDomain(UserEntity entity) {
        User user = new User(
                entity.getIdUser(),
                entity.getPersonId(),
                PasswordHash.of(entity.getPasswordHash()),
                Email.of(entity.getEmail()),
                entity.isEmailVerified(),
                entity.getRegistrationDate(),
                entity.getStatus(),
                entity.getFailedLoginAttempts(),
                entity.getLastLoginAt(),
                entity.getProfileImage());
        if (entity.getGoogleSubject() != null) {
            user.bindGoogleAccount(entity.getGoogleSubject());
        }
        return user;
    }
}
