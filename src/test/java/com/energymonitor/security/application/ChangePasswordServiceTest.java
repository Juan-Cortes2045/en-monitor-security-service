package com.energymonitor.security.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.command.ChangePasswordCommand;
import com.energymonitor.security.application.exception.CurrentPasswordMismatchException;
import com.energymonitor.security.application.exception.PasswordPolicyViolationException;
import com.energymonitor.security.application.usecase.ChangePasswordService;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

/**
 * {@code ChangePassword} requirements: the current password is verified through the hasher
 * port, the new password is validated against the policy, and the change is audited.
 */
class ChangePasswordServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-03-01T12:00:00Z"), ZoneOffset.UTC);

    private final UseCaseFixtures.FakeUserPersistencePort users = new UseCaseFixtures.FakeUserPersistencePort();
    private final UseCaseFixtures.FakePasswordHasherPort hasher = new UseCaseFixtures.FakePasswordHasherPort();
    private final UseCaseFixtures.FakePasswordPolicyPersistencePort policies =
            new UseCaseFixtures.FakePasswordPolicyPersistencePort();
    private final UseCaseFixtures.FakeAuditLogPersistencePort audits =
            new UseCaseFixtures.FakeAuditLogPersistencePort();
    private final UseCaseFixtures.FakeIdentifierGeneratorPort identifiers =
            new UseCaseFixtures.FakeIdentifierGeneratorPort();
    private final ChangePasswordService change =
            new ChangePasswordService(users, hasher, policies, audits, identifiers, CLOCK);

    @Test
    void replacesTheHashWhenCurrentPasswordMatches() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);

        change.change(new ChangePasswordCommand("use0000001", UseCaseFixtures.PASSWORD,
                "NewStrong1!", "10.0.0.3"));

        assertTrue(hasher.matches("NewStrong1!", users.findActive("use0000001").orElseThrow().passwordHash()));
        assertEquals(AuditAction.UPDATE, audits.logs().getFirst().action());
    }

    @Test
    void rejectsWrongCurrentPassword() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);

        assertThrows(CurrentPasswordMismatchException.class,
                () -> change.change(new ChangePasswordCommand("use0000001", "WRONG",
                        "NewStrong1!", null)));
        assertTrue(audits.logs().isEmpty());
    }

    @Test
    void rejectsPasswordBelowPolicy() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);

        assertThrows(PasswordPolicyViolationException.class,
                () -> change.change(new ChangePasswordCommand("use0000001", UseCaseFixtures.PASSWORD,
                        "weak", null)));
        assertTrue(audits.logs().isEmpty());
    }
}