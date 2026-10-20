package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.UserSession;
import java.util.List;
import java.util.Optional;

/**
 * Output port for persisting {@link UserSession}.
 *
 * <p>This port is about logins only. Refresh tokens used to be a column here, which made a
 * session and a secret the same thing and left two sources of truth for one credential. They
 * now live in {@link RefreshTokenPersistencePort} as one row per generation, resolved by hash,
 * and this port keeps no operation that takes or returns a secret.
 */
public interface UserSessionPersistencePort {

    /**
     * Inserts a session, or updates the stored row when the same identifier already exists.
     *
     * @param session the domain object
     * @return the same domain object
     */
    UserSession save(UserSession session);

    /**
     * Finds the active session by identifier.
     *
     * @param idUserSession the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    Optional<UserSession> findActive(String idUserSession);

    /**
     * Lists the active sessions of a user, most recent first.
     *
     * @param idUser the owner
     * @return the sessions
     */
    List<UserSession> listActiveByUser(String idUser);
}