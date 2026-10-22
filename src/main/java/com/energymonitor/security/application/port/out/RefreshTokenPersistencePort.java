package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.RefreshToken;
import java.util.List;
import java.util.Optional;

/**
 * Output port for persisting {@link RefreshToken} generations.
 *
 * <p>Every read is expressed in terms the application understands. In particular the lookup is
 * by {@link RefreshToken#tokenHash()}, never by the secret: the adapter receives a hash and
 * returns a domain object, so the raw token never crosses this boundary in a query and cannot
 * end up in a log or a statement trace.
 */
public interface RefreshTokenPersistencePort {

    /**
     * Inserts a generation, or updates the stored row when the same identifier already exists.
     *
     * @param token the domain object
     * @return the same domain object
     */
    RefreshToken save(RefreshToken token);

    /**
     * Finds a generation by the hash of its secret.
     *
     * <p>This is the entry point of the refresh flow: the presented secret is hashed and
     * resolved here, and whether the result is usable, replayed or unusable is decided by the
     * domain afterwards.
     *
     * @param tokenHash the hash of the presented secret
     * @return the domain object, empty when soft-deleted or unknown
     */
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Lists the generations of a family.
     *
     * <p>Used to invalidate a whole chain after a replay. A family holds as many rows as the
     * login has been refreshed, which is small, so they are loaded and revoked through the
     * domain rather than updated with a bulk statement: the state machine in
     * {@link RefreshToken} stays the single place that decides what a valid transition is.
     *
     * @param familyId the family root identifier
     * @return the generations of that family
     */
    List<RefreshToken> listByFamily(String familyId);
}
