package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.UserSessionEntity;
import com.energymonitor.security.adapter.out.persistence.mapper.UserSessionMapper;
import com.energymonitor.security.adapter.out.persistence.repository.UserSessionRepository;
import com.energymonitor.security.application.port.out.UserSessionPersistencePort;
import com.energymonitor.security.domain.model.UserSession;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for {@link UserSession}.
 *
 * <p>Revoking a session maps the revoked domain state onto the stored row. Because the
 * rehydrated {@code revoked} and {@code closedAt} come from the database, the same revocation
 * cannot be applied twice: the domain rule that rejects closing an already closed session is
 * what the adapter enforces by handing it the stored truth.
 */
@Component
public class UserSessionPersistenceAdapter implements UserSessionPersistencePort {

    private final UserSessionRepository repository;
    private final UserSessionMapper mapper;

    public UserSessionPersistenceAdapter(UserSessionRepository repository, UserSessionMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Inserts a session, or updates the stored row when the same identifier already exists.
     *
     * @param session the domain object
     * @return the same domain object
     */
    public UserSession save(UserSession session) {
        UserSessionEntity entity = repository.findById(session.idUserSession())
                .map(existing -> {
                    mapper.applyTo(existing, session);
                    return existing;
                })
                .orElseGet(() -> mapper.toEntity(session));
        repository.save(entity);
        return session;
    }

    /**
     * Finds the active session by identifier.
     *
     * @param idUserSession the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    public Optional<UserSession> findActive(String idUserSession) {
        return repository.findById(idUserSession)
                .filter(entity -> entity.getDeletedAt() == null)
                .map(mapper::toDomain);
    }


    /**
     * Lists the active sessions of a user, most recent first.
     *
     * @param idUser the owner
     * @return the sessions
     */
    public List<UserSession> listActiveByUser(String idUser) {
        return repository.findByUserIdAndDeletedAtIsNullOrderByCreatedAtDesc(idUser).stream()
                .map(mapper::toDomain)
                .toList();
    }
}