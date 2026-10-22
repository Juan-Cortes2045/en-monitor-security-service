package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.RefreshTokenEntity;
import com.energymonitor.security.adapter.out.persistence.support.Instants;
import com.energymonitor.security.domain.model.RefreshToken;
import org.springframework.stereotype.Component;

/**
 * Converts {@link RefreshToken} to and from {@link RefreshTokenEntity}.
 *
 * <p>Every lifecycle stamp is carried across, including the ones that are empty. Dropping them
 * on the way out would rebuild a live-looking row from a retired one, which is precisely the
 * distinction the reuse detection depends on.
 *
 * <p>{@code tokenHash} is copied verbatim and nothing else is derived from it: the mapper is not
 * a place where a secret could be reconstructed.
 */
@Component
public class RefreshTokenMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param token the domain object
     * @return a detached entity ready to be persisted
     */
    public RefreshTokenEntity toEntity(RefreshToken token) {
        RefreshTokenEntity entity = new RefreshTokenEntity();
        applyTo(entity, token);
        return entity;
    }

    /**
     * Copies the domain state onto an already managed entity, for updates.
     *
     * @param entity the managed entity
     * @param token  the domain object holding the new state
     */
    public void applyTo(RefreshTokenEntity entity, RefreshToken token) {
        entity.setIdRefreshToken(token.idRefreshToken());
        entity.setIdUserSession(token.idUserSession());
        entity.setFamilyId(token.familyId());
        entity.setParentId(token.parentId().orElse(null));
        entity.setTokenHash(token.tokenHash());
        entity.setStatus(token.status());
        entity.setCreatedAt(Instants.truncate(token.createdAt()));
        entity.setExpiresAt(Instants.truncate(token.expiresAt()));
        entity.setRotatedAt(Instants.truncate(token.rotatedAt().orElse(null)));
        entity.setRevokedAt(Instants.truncate(token.revokedAt().orElse(null)));
        entity.setRevokedReason(token.revokedReason().orElse(null));
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public RefreshToken toDomain(RefreshTokenEntity entity) {
        return new RefreshToken(
                entity.getIdRefreshToken(),
                entity.getIdUserSession(),
                entity.getFamilyId(),
                entity.getParentId(),
                entity.getTokenHash(),
                entity.getStatus(),
                entity.getCreatedAt(),
                entity.getExpiresAt(),
                entity.getRotatedAt(),
                entity.getRevokedAt(),
                entity.getRevokedReason());
    }
}
