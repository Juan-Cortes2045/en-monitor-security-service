package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.PasswordPolicyEntity;
import com.energymonitor.security.domain.model.PasswordPolicy;
import org.springframework.stereotype.Component;

/**
 * Converts {@link PasswordPolicy} to and from {@link PasswordPolicyEntity}.
 */
@Component
public class PasswordPolicyMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param policy the domain object
     * @return a detached entity ready to be persisted
     */
    public PasswordPolicyEntity toEntity(PasswordPolicy policy) {
        PasswordPolicyEntity entity = new PasswordPolicyEntity();
        applyTo(entity, policy);
        return entity;
    }

    /**
     * Copies the domain state onto an already managed entity, for updates.
     *
     * @param entity the managed entity
     * @param policy the domain object holding the new state
     */
    public void applyTo(PasswordPolicyEntity entity, PasswordPolicy policy) {
        entity.setIdPasswordPolicy(policy.idPasswordPolicy());
        entity.setMinLength(policy.minLength());
        entity.setMaxLength(policy.maxLength());
        entity.setRequireUppercase(policy.requiresUppercase());
        entity.setRequireNumbers(policy.requiresNumbers());
        entity.setRequireSymbols(policy.requiresSymbols());
        entity.setExpirationDays(policy.expirationDays());
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public PasswordPolicy toDomain(PasswordPolicyEntity entity) {
        return new PasswordPolicy(entity.getIdPasswordPolicy(), entity.getMinLength(),
                entity.getMaxLength(), entity.isRequireUppercase(), entity.isRequireNumbers(),
                entity.isRequireSymbols(), entity.getExpirationDays());
    }
}