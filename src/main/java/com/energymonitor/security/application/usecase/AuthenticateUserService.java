package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.AuthenticateUserCommand;
import com.energymonitor.security.application.port.in.AuthenticateUser;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.LoginErrorLogPersistencePort;
import com.energymonitor.security.application.port.out.PasswordHasherPort;
import com.energymonitor.security.application.port.out.PendingRegistrationPersistencePort;
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
 *
 * <p>An account that has not confirmed its email address cannot sign in: the right password
 * answers {@link AuthenticationStatus#EMAIL_NOT_VERIFIED} instead of a session. So does the right
 * password of a registration still waiting for its code, which has no account yet.
 */
public class AuthenticateUserService implements AuthenticateUser {

    private final UserPersistencePort userPort;
    private final PendingRegistrationPersistencePort pendingPort;
    private final PasswordHasherPort passwordHasher;
    private final IdentifierGeneratorPort identifiers;
    private final AuditLogPersistencePort auditLogPort;
    private final LoginErrorLogPersistencePort loginErrorLogPort;
    private final Clock clock;

    public AuthenticateUserService(UserPersistencePort userPort,
                                   PendingRegistrationPersistencePort pendingPort,
                                   PasswordHasherPort passwordHasher,
                                   IdentifierGeneratorPort identifiers,
                                   AuditLogPersistencePort auditLogPort,
                                   LoginErrorLogPersistencePort loginErrorLogPort, Clock clock) {
        this.userPort = userPort;
        this.pendingPort = pendingPort;
        this.passwordHasher = passwordHasher;
        this.identifiers = identifiers;
        this.auditLogPort = auditLogPort;
        this.loginErrorLogPort = loginErrorLogPort;
        this.clock = clock;
    }

    @Override
    public AuthenticationResult authenticate(AuthenticateUserCommand command) {
        Instant now = clock.instant();
        Email email = Email.of(command.email());
        Optional<User> maybe = userPort.findActiveByEmail(email);
        if (maybe.isEmpty() && waitsForVerification(email, command.rawPassword(), now)) {
            // Registered but not verified yet, so there is no account: the owner, who knows the
            // password, is told to verify, exactly as an account with an unverified address is.
            // The trail records what the database holds, which is no account at all.
            loginErrorLogPort.save(
                    LoginErrorLog.userNotFound(identifiers.generate(), command.ipAddress(), now));
            return new AuthenticationResult(AuthenticationStatus.EMAIL_NOT_VERIFIED, Optional.empty());
        }
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

        // No session until the address is confirmed. Checked after the password, so only the
        // owner learns that the account exists and is waiting for its verification code.
        if (!user.isEmailVerified()) {
            loginErrorLogPort.save(error(user, LoginErrorType.EMAIL_NOT_VERIFIED, command.ipAddress(), now));
            return new AuthenticationResult(AuthenticationStatus.EMAIL_NOT_VERIFIED, Optional.empty());
        }

        user.recordSuccessfulLogin(now);
        userPort.save(user);
        auditLogPort.save(AuditLog.login(identifiers.generate(), user, command.ipAddress(), now));
        return new AuthenticationResult(AuthenticationStatus.SUCCESS,
                Optional.of(new AuthenticatedUser(user.idUser(), user.idPerson(), user.email(),
                        user.status(), user.lastLoginAt().orElseThrow(),
                        user.profileImage().orElse(null))));
    }

    private boolean waitsForVerification(Email email, String rawPassword, Instant now) {
        return pendingPort.findByEmail(email)
                .filter(pending -> !pending.isExpiredAt(now))
                .filter(pending -> passwordHasher.matches(rawPassword, pending.passwordHash()))
                .isPresent();
    }

        private LoginErrorLog error(User user, LoginErrorType type, String ipAddress, Instant now) {
        return new LoginErrorLog(identifiers.generate(), user.idUser(), type, null, ipAddress, now);
    }
}