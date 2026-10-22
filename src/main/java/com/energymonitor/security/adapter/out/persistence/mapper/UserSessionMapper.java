package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.UserSessionEntity;
import com.energymonitor.security.adapter.out.persistence.support.Instants;
import com.energymonitor.security.domain.model.UserSession;
import org.springframework.stereotype.Component;

/**
 * Converts {@link UserSession} to and from {@link UserSessionEntity}.
 *
 * <p>Revocation, its instant, its reason and {@code closedAt} must survive the round trip,
 * otherwise the
 * rehydration constructor would rebuild an open session from a row the domain had closed.
 * The rehydrated {@code closedAt} also lets the parent revoke the session a second time via
 * the domain rule on closed sessions, so a stale session can never stay open by accident.
 */
@Component
public class UserSessionMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param session the domain object
     * @return a detached entity ready to be persisted
     */
    public UserSessionEntity toEntity(UserSession session) {
        UserSessionEntity entity = new UserSessionEntity();
        applyTo(entity, session);
        return entity;
    }

    /**
     * Copies the domain state onto an already managed entity, for updates (revocation).
     *
     * @param entity  the managed entity
     * @param session the domain object holding the new state
     */
    public void applyTo(UserSessionEntity entity, UserSession session) {
        entity.setIdUserSession(session.idUserSession());
        entity.setUserId(session.idUser());
        entity.setRevoked(session.isRevoked());
        entity.setIpAddress(session.ipAddress().orElse(null));
        entity.setUserAgent(session.userAgent().orElse(null));
        entity.setExpirationAt(Instants.truncate(session.expirationAt()));
        entity.setClosedAt(Instants.truncate(session.closedAt().orElse(null)));
        entity.setRevokedAt(Instants.truncate(session.revokedAt().orElse(null)));
        entity.setRevokedReason(session.revokedReason().orElse(null));
        entity.setCreatedAt(Instants.truncate(session.createdAt()));
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public UserSession toDomain(UserSessionEntity entity) {
        return new UserSession(
                entity.getIdUserSession(),
                entity.getUserId(),
                entity.getCreatedAt(),
                entity.getExpirationAt(),
                entity.getIpAddress(),
                entity.getUserAgent(),
                entity.isRevoked(),
                entity.getRevokedAt(),
                entity.getRevokedReason(),
                entity.getClosedAt());
    }
}