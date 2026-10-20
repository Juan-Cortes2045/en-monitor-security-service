package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.RefreshTokenEntity;
import com.energymonitor.security.adapter.out.persistence.mapper.RefreshTokenMapper;
import com.energymonitor.security.adapter.out.persistence.repository.RefreshTokenRepository;
import com.energymonitor.security.application.port.out.RefreshTokenPersistencePort;
import com.energymonitor.security.domain.model.RefreshToken;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for {@link RefreshToken}.
 */
@Component
public class RefreshTokenPersistenceAdapter implements RefreshTokenPersistencePort {

    private final RefreshTokenRepository repository;
    private final RefreshTokenMapper mapper;

    public RefreshTokenPersistenceAdapter(RefreshTokenRepository repository,
            RefreshTokenMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Inserts or updates the generation.
     *
     * @param token the domain object
     * @return the same domain object
     */
    @Override
    public RefreshToken save(RefreshToken token) {
        RefreshTokenEntity entity = repository.findById(token.idRefreshToken())
                .map(existing -> {
                    mapper.applyTo(existing, token);
                    return existing;
                })
                .orElseGet(() -> mapper.toEntity(token));
        repository.save(entity);
        return token;
    }

    /**
     * Finds a generation by the hash of its secret.
     *
     * @param tokenHash the hash to resolve
     * @return the domain object, empty when soft-deleted or unknown
     */
    @Override
    public Optional<RefreshToken> findByTokenHash(String tokenHash) {
        return repository.findByTokenHashAndDeletedAtIsNull(tokenHash)
                .map(mapper::toDomain);
    }

    /**
     * Lists the generations of a family, oldest first.
     *
     * @param familyId the family root identifier
     * @return the generations of that family
     */
    @Override
    public List<RefreshToken> listByFamily(String familyId) {
        return repository.findByFamilyIdAndDeletedAtIsNullOrderByCreatedAtAsc(familyId).stream()
                .map(mapper::toDomain)
                .toList();
    }
}
