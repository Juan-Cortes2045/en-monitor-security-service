package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.LogoutUserSessionCommand;
import com.energymonitor.security.application.exception.SessionNotFoundException;
import com.energymonitor.security.application.port.in.LogoutUserSession;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.UserSessionPersistencePort;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.UserSession;
import java.time.Clock;
import java.time.Instant;

/**
 * Ends an authenticated session and records the event in the audit trail.
 *
 * <p>This use case backs {@code POST /auth/logout}, so it is the ordinary end of a session and
 * it closes rather than revokes. The domain separates the two events deliberately: closing is
 * the holder walking away, revoking is a security invalidation, and collapsing them would make
 * a logout indistinguishable from a compromise when the row is read back during an incident.
 *
 * <p>Nothing here marks the session revoked. A logged-out session is closed and inactive; it
 * is not evidence of a compromise, and keeping the two apart is what lets an audit tell them
 * apart later.
 */
public class LogoutUserSessionService implements LogoutUserSession {

    private final UserSessionPersistencePort sessionPort;
    private final AuditLogPersistencePort auditLogPort;
    private final IdentifierGeneratorPort identifiers;
    private final Clock clock;

    public LogoutUserSessionService(UserSessionPersistencePort sessionPort,
                                    AuditLogPersistencePort auditLogPort,
                                    IdentifierGeneratorPort identifiers, Clock clock) {
        this.sessionPort = sessionPort;
        this.auditLogPort = auditLogPort;
        this.identifiers = identifiers;
        this.clock = clock;
    }

    @Override
    public void logout(LogoutUserSessionCommand command) {
        Instant now = clock.instant();
        UserSession session = sessionPort.findActive(command.idUserSession())
                .orElseThrow(() -> new SessionNotFoundException("no active session " + command.idUserSession()));
        // Logout is an ordinary termination, so the session is closed. It stays unrevoked, which
        // is the whole point of the distinction: this is not a security event.
        session.close(now);
        sessionPort.save(session);
        auditLogPort.save(new AuditLog(identifiers.generate(), session.idUser(), AuditAction.LOGOUT,
                null, command.ipAddress(), null, now));
    }
}