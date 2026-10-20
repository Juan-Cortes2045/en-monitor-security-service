package com.energymonitor.security.adapter.out.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.port.out.PasswordPolicyPersistencePort;
import com.energymonitor.security.domain.model.PasswordPolicy;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import jakarta.persistence.EntityManager;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

/**
 * The password policy seeded by Liquibase changeset security-019.
 *
 * <p>RegisterUserService, ResetPasswordService and ChangePasswordService all read the policy
 * through {@code PasswordPolicyPersistencePort.activePolicy()} and fail with
 * {@code IllegalStateException} when it is absent, which is what made a freshly built database
 * answer HTTP 500 on registration. This test deliberately goes through that same port instead of
 * querying the table directly, so it fails if the seed ever stops being reachable by the
 * application rather than merely failing if a row is missing.
 *
 * <p>Not transactional on purpose: the point is to assert the state Liquibase committed at
 * startup, not a state this test set up itself.
 */
@SpringBootTest
class PasswordPolicySeedTest extends JwtKeyedTest {

    private static final String SEEDED_POLICY_ID = "pol0000001";

    @Autowired
    private PasswordPolicyPersistenceAdapter policies;

    /** Injected by its output port, so this exercises the very accessor the use cases call. */
    @Autowired
    private PasswordPolicyPersistencePort policyPort;

    @Autowired
    private EntityManager entityManager;

    @Test
    @DisplayName("the seeded policy is reachable through the port the use cases use")
    void seededPolicyIsActiveThroughThePort() {
        Optional<PasswordPolicy> policy = policyPort.activePolicy();

        assertTrue(policy.isPresent(),
                "security-019 must leave a policy that activePolicy() can resolve");
        assertEquals(SEEDED_POLICY_ID, policy.orElseThrow().idPasswordPolicy());
    }

    @Test
    @DisplayName("the seeded policy carries the values the fixtures exercise")
    void seededPolicyCarriesTheExpectedValues() {
        PasswordPolicy policy = policyPort.activePolicy().orElseThrow();

        assertEquals(8, policy.minLength());
        assertEquals(64, policy.maxLength());
        assertTrue(policy.requiresUppercase());
        assertTrue(policy.requiresNumbers());
        assertTrue(policy.requiresSymbols());
        assertEquals(90, policy.expirationDays());
    }

    @Test
    @DisplayName("the seeded policy is active, that is not soft deleted")
    void seededPolicyIsNotSoftDeleted() {
        PasswordPolicy policy = policies.findActive(SEEDED_POLICY_ID).orElseThrow();

        assertEquals(SEEDED_POLICY_ID, policy.idPasswordPolicy());

        Object deletedAt = entityManager
                .createNativeQuery("SELECT deleted_at FROM password_policy "
                        + "WHERE id_password_policy = ?1")
                .setParameter(1, SEEDED_POLICY_ID)
                .getSingleResult();

        assertTrue(deletedAt == null, "the seeded policy must stay active, deleted_at must be null");
    }

    @Test
    @DisplayName("activePolicy() cannot be ambiguous: exactly one active row is seeded")
    void exactlyOneActivePolicyIsSeeded() {
        assertEquals(1, policies.findAllActive().size(),
                "activePolicy() takes the first active row without an ORDER BY, so a second "
                        + "active policy would make the applied rules non-deterministic");
    }

    @Test
    @DisplayName("the seeded rules are what registration actually enforces")
    void seededRulesRejectWeakPasswordsAndAcceptCompliantOnes() {
        PasswordPolicy policy = policyPort.activePolicy().orElseThrow();

        assertFalse(policy.isSatisfiedBy("Aa1!x"), "below min_length 8");
        assertFalse(policy.isSatisfiedBy("Aa1securepass"), "missing a symbol");
        assertFalse(policy.isSatisfiedBy("aa1!securepass"), "missing an upper-case letter");
        assertFalse(policy.isSatisfiedBy("Aa!securepass"), "missing a digit");
        assertTrue(policy.isSatisfiedBy("Aa1!securepass"));
    }
}