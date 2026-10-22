package com.energymonitor.security.adapter.out.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.port.out.SecurityConfigurationPersistencePort;
import com.energymonitor.security.application.port.out.UserConfigurationPersistencePort;
import com.energymonitor.security.domain.model.PasswordPolicy;
import com.energymonitor.security.domain.model.SecurityConfiguration;
import com.energymonitor.security.domain.model.UserConfiguration;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

/**
 * Round trips of the configuration tables: {@code password_policy},
 * {@code security_configuration} and {@code user_configuration}.
 */
@SpringBootTest
@Transactional
class ConfigurationPolicyPersistenceTest extends JwtKeyedTest {

    private static final String USER_ID = "use0000001";
    private static final String POLICY_ID = "pol0000001";
    private static final String SESSION_CONFIG_ID = "seg0000001";
    private static final String USER_CONFIG_ID = "cfg0000001";

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private PasswordPolicyPersistenceAdapter policies;

    @Autowired
    private SecurityConfigurationPersistenceAdapter securityConfigurations;

    /**
     * The same adapter resolved by its output port rather than by its concrete class. The
     * application layer is only able to reach these rows if the port exists and the adapter
     * declares it, so injecting by interface is the guard against the adapter regressing into
     * a component with nothing behind it.
     */
    @Autowired
    private SecurityConfigurationPersistencePort securityConfigurationPort;

    @Autowired
    private UserConfigurationPersistenceAdapter userConfigurations;

    /** Injected by its output port, for the same inversion guarantee as the system settings. */
    @Autowired
    private UserConfigurationPersistencePort userConfigurationPort;

    @Autowired
    private PersonPersistenceAdapter persons;

    @Autowired
    private UserPersistenceAdapter users;

    private void flushAndClear() {
        entityManager.flush();
        entityManager.clear();
    }

    @Test
    void passwordPolicyFlagsAndLimitsRoundTrip() {
        policies.save(new PasswordPolicy(POLICY_ID, 8, 64, true, true, false, 90));
        flushAndClear();

        PasswordPolicy read = policies.findActive(POLICY_ID).orElseThrow();
        assertEquals(8, read.minLength());
        assertEquals(64, read.maxLength());
        assertTrue(read.requiresUppercase());
        assertTrue(read.requiresNumbers());
        assertFalse(read.requiresSymbols());
        assertEquals(90, read.expirationDays());
        assertTrue(read.isSatisfiedBy("Strong1pass"));
        assertEquals(1, policies.findAllActive().size());
    }

    @Test
    void securityConfigurationOptionalDescriptionRoundTrips() {
        securityConfigurations.save(
                new SecurityConfiguration(SESSION_CONFIG_ID, "MAX_LOGIN_ATTEMPTS", "5", null));
        flushAndClear();

        SecurityConfiguration withoutDescription =
                securityConfigurations.findActiveByName("MAX_LOGIN_ATTEMPTS").orElseThrow();
        assertEquals(SESSION_CONFIG_ID, withoutDescription.idSecurityConfiguration());
        assertEquals("5", withoutDescription.configValue());
        assertTrue(withoutDescription.description().isEmpty());

        SecurityConfiguration withDescription = new SecurityConfiguration(SESSION_CONFIG_ID,
                "MAX_LOGIN_ATTEMPTS", "3", "Failed logins allowed before blocking");
        securityConfigurations.save(withDescription);
        flushAndClear();

        SecurityConfiguration updated =
                securityConfigurations.findActive(SESSION_CONFIG_ID).orElseThrow();
        assertEquals("3", updated.configValue());
        assertEquals("Failed logins allowed before blocking",
                updated.description().orElseThrow());
    }

    @Test
    void securityConfigurationIsReachableThroughItsOutputPort() {
        securityConfigurationPort.save(
                new SecurityConfiguration(SESSION_CONFIG_ID, "lockout.max_attempts", "5",
                        "Failed logins allowed before blocking"));
        flushAndClear();

        // Read back through the port by the key the application knows it by, which is the shape
        // the failed-login protection will use.
        SecurityConfiguration setting =
                securityConfigurationPort.findActiveByName("lockout.max_attempts").orElseThrow();

        assertEquals("5", setting.configValue());
        assertEquals(SESSION_CONFIG_ID, setting.idSecurityConfiguration());
    }

    @Test
    void securityConfigurationThroughPortReportsMissingKeysRatherThanFailing() {
        assertTrue(securityConfigurationPort.findActiveByName("no.such.setting").isEmpty());
    }

    @Test
    void userConfigurationIsReachableThroughItsOutputPort() {
        PersistenceFixtures.seedUser(persons, users);
        userConfigurationPort.save(UserConfiguration.withDefaults(USER_CONFIG_ID, USER_ID));
        flushAndClear();

        UserConfiguration read =
                userConfigurationPort.findActiveByUser(USER_ID).orElseThrow();

        assertTrue(read.notifyByEmail());
        assertTrue(read.notifyByPush());
        assertTrue(read.socialProvider().isEmpty());
    }

    @Test
    void userConfigurationDefaultAndCustomRoundTrip() {
        PersistenceFixtures.seedUser(persons, users);
        userConfigurations.save(UserConfiguration.withDefaults(USER_CONFIG_ID, USER_ID));
        flushAndClear();

        UserConfiguration defaults = userConfigurations.findActiveByUser(USER_ID).orElseThrow();
        assertTrue(defaults.notifyByEmail());
        assertTrue(defaults.notifyByPush());
        assertTrue(defaults.colorTheme().isEmpty());
        assertTrue(defaults.language().isEmpty());
        assertTrue(defaults.socialProvider().isEmpty());

        UserConfiguration custom = new UserConfiguration(USER_CONFIG_ID, USER_ID,
                false, true, "dark", "es", "google");
        userConfigurations.save(custom);
        flushAndClear();

        UserConfiguration stored = userConfigurations.findActive(USER_CONFIG_ID).orElseThrow();
        assertFalse(stored.notifyByEmail());
        assertTrue(stored.notifyByPush());
        assertEquals("dark", stored.colorTheme().orElseThrow());
        assertEquals("es", stored.language().orElseThrow());
        assertEquals("google", stored.socialProvider().orElseThrow());
    }
}