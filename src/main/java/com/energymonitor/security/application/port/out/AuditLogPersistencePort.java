package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.AuditLog;
import java.util.Optional;

/**
 * Output port for persisting {@link AuditLog} entries.
 */
public interface AuditLogPersistencePort {

    /**
     * Inserts an audit entry.
     *
     * @param log the domain object
     * @return the same domain object
     */
    AuditLog save(AuditLog log);

    /**
     * Finds the entry by identifier.
     *
     * @param idAuditLog the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    Optional<AuditLog> findActive(String idAuditLog);
}