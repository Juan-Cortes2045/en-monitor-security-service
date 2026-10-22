package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.LoginErrorLogEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code login_error_log}.
 */
@Repository
public interface LoginErrorLogRepository extends JpaRepository<LoginErrorLogEntity, String> {
}