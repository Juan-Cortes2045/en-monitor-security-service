package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.LoginErrorLog;
import java.util.List;
import java.util.Optional;

/**
 * Output port for persisting {@link LoginErrorLog} entries.
 */
public interface LoginErrorLogPersistencePort {

    /**
     * Inserts a failed-attempt record.
     *
     * @param log the domain object
     * @return the same domain object
     */
    LoginErrorLog save(LoginErrorLog log);

    /**
     * Finds the active entry by identifier.
     *
     * @param idLoginError the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    Optional<LoginErrorLog> findActive(String idLoginError);

    /**
     * Lists every logged failure, newest first.
     *
     * @return the failures
     */
    List<LoginErrorLog> listNewestFirst();
}