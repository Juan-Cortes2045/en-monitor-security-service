package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.RefreshTokenEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code refresh_token}.
 *
 * <p>The lookup is by hash and nothing else. There is deliberately no finder taking a raw
 * secret, so there is no code path that could query the table with a usable credential.
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, String> {

    /**
     * Finds a generation by the hash of its secret.
     *
     * @param tokenHash the hash to resolve
     * @return the row, empty when soft-deleted or unknown
     */
    Optional<RefreshTokenEntity> findByTokenHashAndDeletedAtIsNull(String tokenHash);

    /**
     * Lists every generation of a family.
     *
     * @param familyId the family root identifier
     * @return the rows of that family, active and retired alike
     */
    List<RefreshTokenEntity> findByFamilyIdAndDeletedAtIsNullOrderByCreatedAtAsc(String familyId);
}
