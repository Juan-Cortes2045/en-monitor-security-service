package com.energymonitor.security.infrastructure;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.willThrow;

import com.energymonitor.security.adapter.out.persistence.repository.AuditLogRepository;
import com.energymonitor.security.adapter.out.persistence.repository.LoginErrorLogRepository;
import com.energymonitor.security.adapter.out.persistence.repository.PersonRepository;
import com.energymonitor.security.adapter.out.persistence.repository.UserRepository;
import com.energymonitor.security.application.command.AuthenticateUserCommand;
import com.energymonitor.security.application.port.in.AuthenticateUser;
import com.energymonitor.security.application.port.out.LoginErrorLogPersistencePort;
import com.energymonitor.security.application.port.out.PersonPersistencePort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordHash;
import com.energymonitor.security.domain.model.Person;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

/**
 * Proves the transaction boundary rolls back rather than merely being declared.
 *
 * <p>A proxy check can prove a boundary exists but not that it commits atomically, so this test
 * breaks a multi-write flow in the middle and looks at the database. The authentication flow is
 * a good candidate: on a wrong password it first increments the account's failure counter and
 * saves it, then records the typed error. If the second write fails, the counter must go back to
 * its previous value, otherwise a storage error would silently lock a legitimate caller out
 * after enough attempts while the audit trail claims nothing happened.
 *
 * <p>The test deliberately does not run in a transaction of its own, since that would hide the
 * behaviour under test; it plants and removes its own rows instead.
 */
@SpringBootTest
class SecurityTransactionRollbackTest extends JwtKeyedTest {

    private static final String PASSWORD =
            "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Instant REGISTRATION = Instant.parse("2026-01-02T03:04:05Z");

    @Autowired
    private AuthenticateUser authenticateUser;

    @Autowired
    private PersonPersistencePort persons;

    @Autowired
    private UserPersistencePort users;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PersonRepository personRepository;

    @Autowired
    private LoginErrorLogRepository loginErrorLogRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @MockitoSpyBean
    private LoginErrorLogPersistencePort loginErrorLog;

    private String userId;
    private String personId;
    private Email email;

    @BeforeEach
    void seedAccount() {
        // Both identifiers must fit the VARCHAR(10) business-key columns.
        String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 7);
        personId = "per" + suffix;
        userId = "use" + suffix;
        email = Email.of("rollback-" + suffix + "@example.com");
        persons.save(new Person(personId, "Ada", "Lovelace"));
        users.save(new User(userId, personId, PasswordHash.of(PASSWORD), email, true,
                REGISTRATION, UserStatus.ACTIVE, 0, null, null));
    }

    @AfterEach
    void removeAccount() {
        loginErrorLogRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteById(userId);
        personRepository.deleteById(personId);
    }

    @Test
    void discardsTheFailureCounterWhenTheErrorTrailCannotBeWritten() {
        willThrow(new IllegalStateException("simulated storage failure"))
                .given(loginErrorLog).save(any());

        assertThrows(IllegalStateException.class,
                () -> authenticateUser.authenticate(new AuthenticateUserCommand(
                        email.value(), "wrong-password", "10.0.0.1")));
    }

    @Test
    void leavesTheAccountUntouchedAfterAFailedMultiWriteFlow() {
        willThrow(new IllegalStateException("simulated storage failure"))
                .given(loginErrorLog).save(any());

        assertThrows(IllegalStateException.class,
                () -> authenticateUser.authenticate(new AuthenticateUserCommand(
                        email.value(), "wrong-password", "10.0.0.1")));

        User reloaded = users.findActiveByEmail(email).orElseThrow();
        assertEquals(0, reloaded.failedLoginAttempts(),
                "The failure counter was committed even though the flow failed");
        assertTrue(reloaded.lastLoginAt().isEmpty());
        assertEquals(UserStatus.ACTIVE, reloaded.status());
    }

    @Test
    void writesNothingToTheErrorTrailWhenTheFlowFails() {
        willThrow(new IllegalStateException("simulated storage failure"))
                .given(loginErrorLog).save(any());

        assertThrows(IllegalStateException.class,
                () -> authenticateUser.authenticate(new AuthenticateUserCommand(
                        email.value(), "wrong-password", "10.0.0.1")));

        assertEquals(0, loginErrorLogRepository.count(),
                "A partially applied flow left an error row behind");
    }
}
