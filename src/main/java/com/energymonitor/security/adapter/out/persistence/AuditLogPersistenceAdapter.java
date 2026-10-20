package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.AuditLogEntity;
import com.energymonitor.security.adapter.out.persistence.mapper.AuditLogMapper;
import com.energymonitor.security.adapter.out.persistence.repository.AuditLogRepository;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.domain.model.AuditLog;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for {@link AuditLog}.
 *
 * <p>Audit entries are append-only and carry their business event time in {@code created_at}.
 * This adapter only inserts and reads; it never edits or deletes a row, matching the
 * immutable domain object the application logs.
 */
@Component
public class AuditLogPersistenceAdapter implements AuditLogPersistencePort {

    private final AuditLogRepository repository;
    private final AuditLogMapper mapper;

    public AuditLogPersistenceAdapter(AuditLogRepository repository, AuditLogMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Inserts an audit entry.
     *
     * @param log the domain object
     * @return the same domain object
     */
    public AuditLog save(AuditLog log) {
        repository.save(mapper.toEntity(log));
        return log;
    }

    /**
     * Finds the entry by identifier.
     *
     * @param idAuditLog the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    public Optional<AuditLog> findActive(String idAuditLog) {
        return repository.findById(idAuditLog)
                .filter(entity -> entity.getDeletedAt() == null)
                .map(mapper::toDomain);
    }
}