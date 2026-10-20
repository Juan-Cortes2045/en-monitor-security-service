package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.PasswordResetTokenEntity;
import com.energymonitor.security.adapter.out.persistence.support.Instants;
import com.energymonitor.security.domain.model.PasswordResetToken;
import org.springframework.stereotype.Component;

/**
 * Converts {@link PasswordResetToken} to and from {@link PasswordResetTokenEntity}.
 *
 * <p>Only the hash crosses this boundary. {@code PasswordResetToken} carries the clear secret
 * for as long as the request that issued it lasts, and this mapper is the one place that could
 * have written it out; it reads the hash instead and has no line that could do otherwise.
 *
 * <p>{@code used} is the rest of the mapping: it must survive the round trip, or a consumed
 * token would come back looking redeemable. The rehydration factory is the one that takes
 * {@code used} explicitly, and this mapper preserves the flag as stored.
 *
 * <p>The issue and expiry instants are truncated to whole seconds, matching the column
 * precision, so a stored token rehydrates without a rotation of nanoseconds.
 */
@Component
public class PasswordResetTokenMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param token the domain object
     * @return a detached entity ready to be persisted
     */
    public PasswordResetTokenEntity toEntity(PasswordResetToken token) {
        PasswordResetTokenEntity entity = new PasswordResetTokenEntity();
        entity.setIdResetToken(token.idResetToken());
        entity.setUserId(token.idUser());
        entity.setResetTokenHash(token.resetTokenHash());
        entity.setUsed(token.isUsed());
        entity.setAttempts(token.attempts());
        entity.setExpirationAt(Instants.truncate(token.expirationAt()));
        entity.setCreatedAt(Instants.truncate(token.createdAt()));
        return entity;
    }

    /**
     * Copies the domain state onto an already managed entity, for updates.
     *
     * <p>{@code created_at} is not touched here: the entity keeps the issue instant that was
     * stored on insert, and {@code updated_at} is refreshed by the audit callback. The hash is
     * rewritten from the domain rather than left alone, so the column and the object cannot
     * drift apart.
     *
     * <p>{@code attempts} is deliberately not written on this path. The count is spent by a
     * conditional update in the repository, and a bulk write from a domain object read earlier
     * could put back a value the database has already moved past, undoing a reservation that
     * another request is relying on.
     *
     * @param entity the managed entity
     * @param token  the domain object holding the new state
     */
    public void applyTo(PasswordResetTokenEntity entity, PasswordResetToken token) {
        entity.setUserId(token.idUser());
        entity.setResetTokenHash(token.resetTokenHash());
        entity.setUsed(token.isUsed());
        entity.setExpirationAt(Instants.truncate(token.expirationAt()));
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * <p>There is no clear secret to restore, because the row never held one: the token that
     * comes back knows its hash and nothing else.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public PasswordResetToken toDomain(PasswordResetTokenEntity entity) {
        return PasswordResetToken.rehydrate(
                entity.getIdResetToken(),
                entity.getUserId(),
                entity.getResetTokenHash(),
                entity.getCreatedAt(),
                entity.getExpirationAt(),
                entity.isUsed(),
                entity.getAttempts());
    }
}
