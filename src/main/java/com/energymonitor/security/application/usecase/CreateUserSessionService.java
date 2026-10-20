package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.CreateUserSessionCommand;
import com.energymonitor.security.application.exception.AccountNotActiveException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.CreateUserSession;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.application.port.out.UserSessionPersistencePort;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserSession;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Opens a new authenticated session for an account.
 */
public class CreateUserSessionService implements CreateUserSession {

    private static final Duration TTL = Duration.ofDays(7);

    private final UserPersistencePort userPort;
    private final UserSessionPersistencePort sessionPort;
    private final IdentifierGeneratorPort identifiers;
    private final Clock clock;

    public CreateUserSessionService(UserPersistencePort userPort,
                                    UserSessionPersistencePort sessionPort,
                                    IdentifierGeneratorPort identifiers, Clock clock) {
        this.userPort = userPort;
        this.sessionPort = sessionPort;
        this.identifiers = identifiers;
        this.clock = clock;
    }

    @Override
    public UserSession create(CreateUserSessionCommand command) {
        Instant now = clock.instant();
        User user = userPort.findActive(command.idUser())
                .orElseThrow(() -> new UserNotFoundException("no active user " + command.idUser()));
        if (!user.canAuthenticate()) {
            throw new AccountNotActiveException("account " + user.idUser() + " is " + user.status() + " and cannot open a session");
        }
        UserSession session = UserSession.open(identifiers.generate(), user.idUser(),
                now, now.plus(TTL), command.ipAddress(), command.userAgent());
        return sessionPort.save(session);
    }
}