package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.AuthenticateUserCommand;
import com.energymonitor.security.application.port.in.AuthenticateUser;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.LoginErrorLogPersistencePort;
import com.energymonitor.security.application.port.out.PasswordHasherPort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.application.result.AuthenticatedUser;
import com.energymonitor.security.application.result.AuthenticationResult;
import com.energymonitor.security.application.result.AuthenticationStatus;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.LoginErrorLog;
import com.energymonitor.security.domain.model.LoginErrorType;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * Authenticates an account, recording every attempt in the typed error or audit trail.
 */
public class AuthenticateUserService implements AuthenticateUser {

    private final UserPersistencePort userPort;
    private final PasswordHasherPort passwordHasher;
    private final IdentifierGeneratorPort identifiers;
    private final AuditLogPersistencePort auditLogPort;
    private final LoginErrorLogPersistencePort loginErrorLogPort;
    private final Clock clock;

    public AuthenticateUserService(UserPersistencePort userPort, PasswordHasherPort passwordHasher,
                                   IdentifierGeneratorPort identifiers,
                                   AuditLogPersistencePort auditLogPort,
                                   LoginErrorLogPersistencePort loginErrorLogPort, Clock clock) {
        this.userPort = userPort;
        this.passwordHasher = passwordHasher;
        this.identifiers = identifiers;
        this.auditLogPort = auditLogPort;
        this.loginErrorLogPort = loginErrorLogPort;
        this.clock = clock;
    }

    @Override
    public AuthenticationResult authenticate(AuthenticateUserCommand command) {
        Instant now = clock.instant();
        Optional<User> maybe = userPort.findActiveByEmail(Email.of(command.email()));
        if (maybe.isEmpty()) {
            loginErrorLogPort.save(
                    LoginErrorLog.userNotFound(identifiers.generate(), command.ipAddress(), now));
            return new AuthenticationResult(AuthenticationStatus.USER_NOT_FOUND, Optional.empty());
        }

        User user = maybe.get();
        UserStatus status = user.status();
        if (status == UserStatus.BLOCKED) {
            loginErrorLogPort.save(error(user, LoginErrorType.ACCOUNT_BLOCKED, command.ipAddress(), now));
            return new AuthenticationResult(AuthenticationStatus.ACCOUNT_BLOCKED, Optional.empty());
        }
        if (status == UserStatus.INACTIVE) {
            loginErrorLogPort.save(error(user, LoginErrorType.ACCOUNT_INACTIVE, command.ipAddress(), now));
            return new AuthenticationResult(AuthenticationStatus.ACCOUNT_INACTIVE, Optional.empty());
        }

        if (!passwordHasher.matches(command.rawPassword(), user.passwordHash())) {
            user.incrementFailedLoginAttempts();
            userPort.save(user);
            loginErrorLogPort.save(error(user, LoginErrorType.INVALID_PASSWORD, command.ipAddress(), now));
            return new AuthenticationResult(AuthenticationStatus.INVALID_CREDENTIALS, Optional.empty());
        }

        user.recordSuccessfulLogin(now);
        userPort.save(user);
        auditLogPort.save(AuditLog.login(identifiers.generate(), user, command.ipAddress(), now));
        return new AuthenticationResult(AuthenticationStatus.SUCCESS,
                Optional.of(new AuthenticatedUser(user.idUser(), user.idPerson(), user.email(),
                        user.status(), user.lastLoginAt().orElseThrow(),
                        user.profileImage().orElse(null))));
    }

    private LoginErrorLog error(User user, LoginErrorType type, String ipAddress, Instant now) {
        return new LoginErrorLog(identifiers.generate(), user.idUser(), type, null, ipAddress, now);
    }
}