package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.SecurityOutboxEntity;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code security_outbox}.
 */
@Repository
public interface SecurityOutboxRepository extends JpaRepository<SecurityOutboxEntity, String> {

    /**
     * The messages still waiting for the broker, oldest first, so the order in which changes
     * happened is the order in which other services hear about them.
     */
    @Query("""
            select m from SecurityOutboxEntity m
            where m.publishedAt is null and m.discardedAt is null
            order by m.occurredAt asc, m.idMessage asc
            """)
    List<SecurityOutboxEntity> findPending(Pageable page);
}
