package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.AuditLogEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code audit_log}.
 *
 * <p>Audit entries are append-only: rows are inserted by the domain and never modified. The
 * base repository's delete operations are therefore unused by the adapters; they exist only
 * because {@link JpaRepository} declares them and kept as-is for future administration needs.
 */
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLogEntity, String> {
}