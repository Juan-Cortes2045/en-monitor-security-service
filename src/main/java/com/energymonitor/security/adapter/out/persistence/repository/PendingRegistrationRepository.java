package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.PendingRegistrationEntity;
import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code pending_registration}.
 */
@Repository
public interface PendingRegistrationRepository extends JpaRepository<PendingRegistrationEntity, String> {

    Optional<PendingRegistrationEntity> findByEmail(String email);

    /** One statement, flushed first, so a request saved in the same transaction is not missed. */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from PendingRegistrationEntity p where p.email = :email")
    int deleteByEmail(@Param("email") String email);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from PendingRegistrationEntity p where p.expiresAt <= :instant")
    int deleteExpired(@Param("instant") Instant instant);
}
