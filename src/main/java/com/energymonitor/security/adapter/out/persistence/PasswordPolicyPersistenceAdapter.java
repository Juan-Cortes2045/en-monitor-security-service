package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.PasswordPolicyEntity;
import com.energymonitor.security.adapter.out.persistence.mapper.PasswordPolicyMapper;
import com.energymonitor.security.adapter.out.persistence.repository.PasswordPolicyRepository;
import com.energymonitor.security.application.port.out.PasswordPolicyPersistencePort;
import com.energymonitor.security.domain.model.PasswordPolicy;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for {@link PasswordPolicy}.
 */
@Component
public class PasswordPolicyPersistenceAdapter implements PasswordPolicyPersistencePort {

    private final PasswordPolicyRepository repository;
    private final PasswordPolicyMapper mapper;

    public PasswordPolicyPersistenceAdapter(PasswordPolicyRepository repository,
            PasswordPolicyMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Inserts or updates the policy.
     *
     * @param policy the domain object
     * @return the same domain object
     */
    public PasswordPolicy save(PasswordPolicy policy) {
        PasswordPolicyEntity entity = repository.findById(policy.idPasswordPolicy())
                .map(existing -> {
                    mapper.applyTo(existing, policy);
                    return existing;
                })
                .orElseGet(() -> mapper.toEntity(policy));
        repository.save(entity);
        return policy;
    }

    /**
     * Finds the active policy by identifier.
     *
     * @param idPasswordPolicy the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    public Optional<PasswordPolicy> findActive(String idPasswordPolicy) {
        return repository.findById(idPasswordPolicy)
                .filter(entity -> entity.getDeletedAt() == null)
                .map(mapper::toDomain);
    }

    /**
     * Lists the active policy rows.
     *
     * @return the active policies
     */
    public List<PasswordPolicy> findAllActive() {
        return repository.findByDeletedAtIsNull().stream()
                .map(mapper::toDomain)
                .toList();
    }
}