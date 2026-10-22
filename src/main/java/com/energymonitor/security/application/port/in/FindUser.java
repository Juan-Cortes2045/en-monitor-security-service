package com.energymonitor.security.application.port.in;

import com.energymonitor.security.domain.model.User;
import java.util.Optional;

/**
 * Input port for reading account state.
 */
public interface FindUser {

    /**
     * @param idUser the identifier
     * @return the active user, empty when soft-deleted or missing
     */
    Optional<User> findByIdentifier(String idUser);

    /**
     * @param email the account address
     * @return the active user, empty when soft-deleted or unknown
     */
    Optional<User> findByEmail(String email);
}