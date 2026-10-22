package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.PasswordPolicyEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code password_policy}.
 */
@Repository
public interface PasswordPolicyRepository extends JpaRepository<PasswordPolicyEntity, String> {

    /**
     * Lists the active policy rows.
     *
     * @return the active rows
     */
    List<PasswordPolicyEntity> findByDeletedAtIsNull();
}