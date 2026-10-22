package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.LoginErrorLogEntity;
import com.energymonitor.security.adapter.out.persistence.support.Instants;
import com.energymonitor.security.domain.model.LoginErrorLog;
import org.springframework.stereotype.Component;

/**
 * Converts {@link LoginErrorLog} to and from {@link LoginErrorLogEntity}.
 *
 * <p>{@code occurredAt} is the business event time and has no dedicated column: the row's
 * {@code created_at} is the only timestamp a failed attempt carries, so that is where the
 * event time is written and where it is read back from. The mapper presets it before
 * persisting; {@code BaseAuditEntity} leaves a preset value untouched.
 *
 * <p>The optional {@code idUser} survives the round trip as {@code null}, which the domain
 * only accepts for {@code USER_NOT_FOUND}; a stored row that pairs a real user with that
 * error type therefore fails loudly instead of rehydrating an impossible object.
 */
@Component
public class LoginErrorLogMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param log the domain object
     * @return a detached entity ready to be persisted
     */
    public LoginErrorLogEntity toEntity(LoginErrorLog log) {
        LoginErrorLogEntity entity = new LoginErrorLogEntity();
        entity.setIdLoginError(log.idLoginError());
        entity.setUserId(log.idUser().orElse(null));
        entity.setErrorType(log.errorType());
        entity.setDescription(log.description().orElse(null));
        entity.setIpAddress(log.ipAddress().orElse(null));
        entity.setCreatedAt(Instants.truncate(log.occurredAt()));
        return entity;
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public LoginErrorLog toDomain(LoginErrorLogEntity entity) {
        return new LoginErrorLog(entity.getIdLoginError(), entity.getUserId(),
                entity.getErrorType(), entity.getDescription(), entity.getIpAddress(),
                entity.getCreatedAt());
    }
}