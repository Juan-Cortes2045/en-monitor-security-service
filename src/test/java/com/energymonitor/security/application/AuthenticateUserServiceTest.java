package com.energymonitor.security.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.command.AuthenticateUserCommand;
import com.energymonitor.security.application.result.AuthenticatedUser;
import com.energymonitor.security.application.result.AuthenticationResult;
import com.energymonitor.security.application.result.AuthenticationStatus;
import com.energymonitor.security.application.usecase.AuthenticateUserService;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.LoginErrorType;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

/**
 * {@code AuthenticateUser} requirements: the account state and the credentials are both
 * classified, every failure lands in the typed error trail, a success lands in the audit
 * trail, and a blocked or inactive account is never recorded as having logged in.
 */
class AuthenticateUserServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-03-01T12:00:00Z"), ZoneOffset.UTC);

    private final UseCaseFixtures.FakeUserPersistencePort users = new UseCaseFixtures.FakeUserPersistencePort();
    private final UseCaseFixtures.FakePasswordHasherPort hasher = new UseCaseFixtures.FakePasswordHasherPort();
    private final UseCaseFixtures.FakeIdentifierGeneratorPort identifiers =
            new UseCaseFixtures.FakeIdentifierGeneratorPort();
    private final UseCaseFixtures.FakeAuditLogPersistencePort audits =
            new UseCaseFixtures.FakeAuditLogPersistencePort();
    private final UseCaseFixtures.FakeLoginErrorLogPersistencePort errors =
            new UseCaseFixtures.FakeLoginErrorLogPersistencePort();
    private final AuthenticateUserService authenticate =
            new AuthenticateUserService(users, hasher, identifiers, audits, errors, CLOCK);

    private AuthenticateUserCommand attempt(String email, String password) {
        return new AuthenticateUserCommand(email, password, "10.0.0.7");
    }

    @Test
    void successesWithCorrectPasswordOnActiveAccount() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);

        AuthenticationResult result = authenticate.authenticate(attempt("ada@example.com", UseCaseFixtures.PASSWORD));

        assertTrue(result.isSuccess());
        assertEquals("use0000001", result.user().orElseThrow().idUser());
        assertEquals(CLOCK.instant(), result.user().orElseThrow().lastLoginAt());
        assertTrue(errors.errors().isEmpty());
        assertEquals(1, audits.logs().size());
        assertEquals(AuditAction.LOGIN, audits.logs().getFirst().action());
    }

    @Test
    void publishesACredentialFreeIdentityInsteadOfTheUserAggregate() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);

        AuthenticationResult result = authenticate.authenticate(attempt("ada@example.com", UseCaseFixtures.PASSWORD));

        AuthenticatedUser identity = result.user().orElseThrow();
        assertEquals("use0000001", identity.idUser());
        assertEquals("per0000001", identity.idPerson());
        assertEquals("ada@example.com", identity.email().value());
        assertEquals(UserStatus.ACTIVE, identity.status());
        assertThrows(NoSuchMethodException.class, () -> AuthenticatedUser.class.getMethod("passwordHash"));
    }

    @Test
    void unknownAccountReturnsUserNotFoundWithoutSavingAnything() {
        AuthenticationResult result = authenticate.authenticate(attempt("nobody@example.com", "x"));

        assertEquals(AuthenticationStatus.USER_NOT_FOUND, result.status());
        assertFalse(result.isSuccess());
        assertEquals(1, errors.errors().size());
        assertEquals(LoginErrorType.USER_NOT_FOUND, errors.errors().getFirst().errorType());
        assertTrue(audits.logs().isEmpty());
    }

    @Test
    void wrongPasswordIncrementsTheFailureCounterAndLogsIt() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.ACTIVE);

        AuthenticationResult result = authenticate.authenticate(attempt("ada@example.com", "WRONG"));

        assertEquals(AuthenticationStatus.INVALID_CREDENTIALS, result.status());
        assertEquals(1, users.findActive("use0000001").orElseThrow().failedLoginAttempts());
        assertEquals(1, errors.errors().size());
        assertEquals(LoginErrorType.INVALID_PASSWORD, errors.errors().getFirst().errorType());
        assertTrue(audits.logs().isEmpty());
    }

    @Test
    void blockedAccountIsClassifiedBeforeCredentialsAreChecked() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.BLOCKED);

        AuthenticationResult result = authenticate.authenticate(attempt("ada@example.com", UseCaseFixtures.PASSWORD));

        assertEquals(AuthenticationStatus.ACCOUNT_BLOCKED, result.status());
        assertEquals(LoginErrorType.ACCOUNT_BLOCKED, errors.errors().getFirst().errorType());
        assertEquals(0, users.findActive("use0000001").orElseThrow().failedLoginAttempts());
        assertTrue(audits.logs().isEmpty());
    }

    @Test
    void inactiveAccountIsClassifiedBeforeCredentialsAreChecked() {
        users.seed("use0000001", "per0000001", "ada@example.com", UserStatus.INACTIVE);

        AuthenticationResult result = authenticate.authenticate(attempt("ada@example.com", UseCaseFixtures.PASSWORD));

        assertEquals(AuthenticationStatus.ACCOUNT_INACTIVE, result.status());
        assertEquals(LoginErrorType.ACCOUNT_INACTIVE, errors.errors().getFirst().errorType());
        assertEquals(0, users.findActive("use0000001").orElseThrow().failedLoginAttempts());
        assertTrue(audits.logs().isEmpty());
    }
}