package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.PasswordPolicy;
import java.util.List;
import java.util.Optional;

/**
 * Output port for persisting {@link PasswordPolicy}.
 */
public interface PasswordPolicyPersistencePort {

    /**
     * Inserts or updates the policy.
     *
     * @param policy the domain object
     * @return the same domain object
     */
    PasswordPolicy save(PasswordPolicy policy);

    /**
     * Finds the active policy by identifier.
     *
     * @param idPasswordPolicy the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    Optional<PasswordPolicy> findActive(String idPasswordPolicy);

    /**
     * Lists the active policy rows.
     *
     * @return the active policies
     */
    List<PasswordPolicy> findAllActive();

    /**
     * The configured password policy, the first active row.
     *
     * @return the policy, empty when none is configured
     */
    default Optional<PasswordPolicy> activePolicy() {
        return findAllActive().stream().findFirst();
    }
}