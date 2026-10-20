package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.UserEntity;
import com.energymonitor.security.adapter.out.persistence.mapper.UserMapper;
import com.energymonitor.security.adapter.out.persistence.repository.UserRepository;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.User;
import java.time.Instant;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for {@link User}.
 *
 * <p>Updates map onto the managed row loaded from the database, so the row's own
 * {@code created_at} survives and only {@code updated_at} is refreshed. A soft-deleted row
 * holding the same identifier is reactivated by clearing {@code deleted_at}, which is the
 * same reuse-by-key behaviour the RBAC assignments rely on.
 */
@Component
public class UserPersistenceAdapter implements UserPersistencePort {

    private final UserRepository repository;
    private final UserMapper mapper;

    public UserPersistenceAdapter(UserRepository repository, UserMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Inserts the user, updates an existing one, or reactivates a soft-deleted row with the
     * same identifier.
     *
     * @param user the domain object
     * @return the same domain object
     */
    public User save(User user) {
        UserEntity entity = repository.findById(user.idUser())
                .map(existing -> {
                    if (existing.getDeletedAt() != null) {
                        existing.setDeletedAt(null);
                    }
                    mapper.applyTo(existing, user);
                    return existing;
                })
                .orElseGet(() -> mapper.toEntity(user));
        repository.save(entity);
        return user;
    }

    /**
     * Finds the active user by identifier.
     *
     * @param idUser the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    public Optional<User> findActive(String idUser) {
        return repository.findById(idUser)
                .filter(entity -> entity.getDeletedAt() == null)
                .map(mapper::toDomain);
    }

    /**
     * Finds the active user by normalised email.
     *
     * @param email the normalised email
     * @return the domain object, empty when soft-deleted or unknown
     */
    public Optional<User> findActiveByEmail(String email) {
        return repository.findByEmailAndDeletedAtIsNull(email)
                .map(mapper::toDomain);
    }

    @Override
    public Optional<User> findActiveByEmail(Email email) {
        return findActiveByEmail(email.value());
    }

    @Override
    public Optional<User> findActiveByGoogleSubject(String googleSubject) {
        return repository.findByGoogleSubjectAndDeletedAtIsNull(googleSubject)
                .map(mapper::toDomain);
    }

    @Override
    public void softDelete(String idUser, Instant deletedAt) {
        repository.findById(idUser).ifPresent(entity -> {
            entity.setDeletedAt(deletedAt);
            entity.setEmail(releasedEmail(idUser));
            repository.save(entity);
        });
    }

    /**
     * What a deleted row keeps instead of its address. Unique per account, valid for
     * {@code Email}, and under {@code .invalid}, a reserved domain (RFC 2606) no real address
     * can belong to.
     */
    static String releasedEmail(String idUser) {
        return "deleted+" + idUser + "@deleted.invalid";
    }
}
