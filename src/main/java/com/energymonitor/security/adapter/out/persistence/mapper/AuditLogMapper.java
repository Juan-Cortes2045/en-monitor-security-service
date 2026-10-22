package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.AuditLogEntity;
import com.energymonitor.security.adapter.out.persistence.support.Instants;
import com.energymonitor.security.domain.model.AuditLog;
import org.springframework.stereotype.Component;

/**
 * Converts {@link AuditLog} to and from {@link AuditLogEntity}.
 *
 * <p>{@code occurredAt} maps to the row's {@code created_at}, the only timestamp an audit
 * entry carries, and is preset before persisting so the event time is preserved exactly.
 *
 * <p>The domain log is immutable, so this mapper has no {@code applyTo} method: editing an
 * audit row is not a state the domain supports. The entity still exposes setters because JPA
 * requires them, but the mapper - and therefore the adapters - never writes over an existing
 * row, only inserts.
 */
@Component
public class AuditLogMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param log the domain object
     * @return a detached entity ready to be persisted
     */
    public AuditLogEntity toEntity(AuditLog log) {
        AuditLogEntity entity = new AuditLogEntity();
        entity.setIdAuditLog(log.idAuditLog());
        entity.setUserId(log.idUser().orElse(null));
        entity.setAction(log.action());
        entity.setDescription(log.description().orElse(null));
        entity.setIpAddress(log.ipAddress().orElse(null));
        entity.setApplication(log.application().orElse(null));
        entity.setCreatedAt(Instants.truncate(log.occurredAt()));
        return entity;
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public AuditLog toDomain(AuditLogEntity entity) {
        return new AuditLog(entity.getIdAuditLog(), entity.getUserId(), entity.getAction(),
                entity.getDescription(), entity.getIpAddress(), entity.getApplication(),
                entity.getCreatedAt());
    }
}