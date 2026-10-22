package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.PasswordResetTokenEntity;
import com.energymonitor.security.adapter.out.persistence.mapper.PasswordResetTokenMapper;
import com.energymonitor.security.adapter.out.persistence.repository.PasswordResetTokenRepository;
import com.energymonitor.security.application.port.out.PasswordResetTokenPersistencePort;
import com.energymonitor.security.domain.model.PasswordResetToken;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Persistence adapter for {@link PasswordResetToken}.
 *
 * <p>What reaches the database is the token hash and its lifecycle, never the clear secret the
 * domain holds in memory while the issuing request is in flight: the mapper has no field for it,
 * so there is nothing here that could write one.
 *
 * <p>Tokens are one-shot: the domain mutates {@code used} and the adapter updates the row by
 * mapping the full domain state onto the existing one. Because the rehydrated domain carries
 * {@code used}, the stored flag is the only source of truth and can never be overridden by a
 * stale in-memory object.
 */
@Component
public class PasswordResetTokenPersistenceAdapter implements PasswordResetTokenPersistencePort {

    private final PasswordResetTokenRepository repository;
    private final PasswordResetTokenMapper mapper;

    public PasswordResetTokenPersistenceAdapter(PasswordResetTokenRepository repository,
            PasswordResetTokenMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Inserts a token. The token's issue instant is written into {@code created_at}.
     *
     * @param token the domain object
     * @return the same domain object
     */
    public PasswordResetToken save(PasswordResetToken token) {
        // Flushed, not merely queued: the caller of save needs the unique constraint on
        // reset_token_hash to be tested here, where its violation can still be translated, rather
        // than at commit, where it would escape as a driver failure nobody was looking for.
        repository.saveAndFlush(mapper.toEntity(token));
        return token;
    }

    /**
     * Updates the state (used flag) of a stored token.
     *
     * @param token the domain object holding the new state
     * @return the same domain object
     */
    public PasswordResetToken update(PasswordResetToken token) {
        PasswordResetTokenEntity entity = repository.findById(token.idResetToken())
                .map(existing -> {
                    mapper.applyTo(existing, token);
                    return existing;
                })
                .orElseGet(() -> mapper.toEntity(token));
        // an existing row's created_at must survive; the insert path presets it
        repository.save(entity);
        return token;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Its own transaction, which is the whole reason it works. The request that presents a code
     * rejects it by raising an exception, and the transaction wrapping that request rolls back
     * every write it made. A counter incremented inside it would be rolled back with it, so the
     * fifth attempt would never be recorded and the limit would never arrive. Suspending the outer
     * transaction for the duration of this one statement commits the count independently of what
     * the caller goes on to do.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean reserveAttempt(String idResetToken) {
        return repository.reserveAttempt(idResetToken) == 1;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Also its own transaction, and for a related reason: the redemption that consumed the code
     * is about to commit a password change, and whether the flag survived must not depend on that
     * commit succeeding.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean markUsedIfPending(String idResetToken) {
        return repository.markUsedIfPending(idResetToken) == 1;
    }

    /**
     * Finds the active token by identifier.
     *
     * @param idResetToken the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    public Optional<PasswordResetToken> findActive(String idResetToken) {
        return repository.findById(idResetToken)
                .filter(entity -> entity.getDeletedAt() == null)
                .map(mapper::toDomain);
    }

    /**
     * Finds the active token by the hash of its secret.
     *
     * @param resetTokenHash the hash to resolve
     * @return the domain object, empty when soft-deleted or unknown
     */
    public Optional<PasswordResetToken> findActiveByHash(String resetTokenHash) {
        return repository.findByResetTokenHashAndDeletedAtIsNull(resetTokenHash)
                .map(mapper::toDomain);
    }

    /**
     * Lists the active tokens of a user, newest first.
     *
     * @param idUser the recipient
     * @return the pending tokens
     */
    public List<PasswordResetToken> listActiveByUser(String idUser) {
        return repository.findByUserIdAndDeletedAtIsNullOrderByCreatedAtDesc(idUser).stream()
                .map(mapper::toDomain)
                .toList();
    }

    /**
     * {@inheritDoc}
     *
     * <p>Consumed through the domain rather than by writing the column directly, so the flag
     * still passes the invariant that a token cannot be consumed twice. The rows are already
     * managed, so the dirty checking of the surrounding transaction is what persists them.
     */
    public int consumeAllForUser(String idUser) {
        List<PasswordResetTokenEntity> pending =
                repository.findByUserIdAndUsedFalseAndDeletedAtIsNullOrderByCreatedAtDesc(idUser);
        for (PasswordResetTokenEntity entity : pending) {
            PasswordResetToken token = mapper.toDomain(entity);
            token.markUsed();
            mapper.applyTo(entity, token);
        }
        return pending.size();
    }
}
