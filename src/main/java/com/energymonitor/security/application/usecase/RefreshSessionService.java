package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.RefreshSessionCommand;
import com.energymonitor.security.application.port.in.RefreshSession;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.RefreshTokenHasherPort;
import com.energymonitor.security.application.port.out.RefreshTokenPersistencePort;
import com.energymonitor.security.application.port.out.TokenGeneratorPort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.application.port.out.UserSessionPersistencePort;
import com.energymonitor.security.application.result.AuthenticatedUser;
import com.energymonitor.security.application.result.RefreshSessionResult;
import com.energymonitor.security.application.result.RefreshStatus;
import com.energymonitor.security.domain.model.AuditAction;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.RefreshToken;
import com.energymonitor.security.domain.model.RefreshTokenStatus;
import com.energymonitor.security.domain.model.RevocationReason;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserSession;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Rotates a refresh token, and treats a replay of a retired one as a security incident.
 *
 * <h2>The exchange</h2>
 *
 * <p>A refresh token is good for exactly one exchange. Presenting an active one retires it and
 * mints its successor in the same family, against the same session. The session is not replaced
 * and no second one is created: rotating a secret is not a new login, so the session keeps its
 * identity and its original creation instant and only slides its expiry.
 *
 * <p>Issuing the replacement access token is deliberately not done here. That belongs to the
 * delivery layer, which is the only place that knows the transport, so this use case concerns
 * itself with the credential chain and reports whether the exchange succeeded.
 *
 * <h2>Why a replay is an incident and not a bad request</h2>
 *
 * <p>A retired token is a genuine secret that has already been spent. Seeing it again means one
 * of two things, and the system cannot tell which: the legitimate client is retrying a request
 * it already had accepted, or somebody kept a copy and is using it now. The safe reading of an
 * ambiguity like that is that the credential leaked, so the entire family is revoked and the
 * session is marked compromised. The legitimate client, if that is who it was, logs in again;
 * an attacker holding one stolen token gets nothing.
 *
 * <p>Answering a replay as a plain rejection would leave the thief and the real user in exactly
 * the same position and would mean the theft was never noticed.
 *
 * <p>Expired and revoked tokens are treated differently on purpose. A client that was merely
 * slow is not a security event, and escalating it would revoke the family every time somebody's
 * clock was wrong.
 *
 * <h2>Known debt: a family has no size limit</h2>
 *
 * <p>Each rotation adds a row and retires the previous one, so a family grows for as long as a
 * client keeps refreshing: R1, R2, R3, R4 and onwards without a ceiling. Nothing here caps it,
 * because the project has never defined a maximum, and inventing a number would silently turn a
 * product decision into an implementation detail. A client that refreshes in a loop therefore
 * accumulates rows, and a family revocation walks all of them.
 *
 * <p>The cost is bounded in practice by the token lifetime, since every generation carries its
 * own {@code expiresAt}, but nothing reclaims the rows, so the growth is permanent for a login
 * that is never explicitly closed.
 *
 * <p>If a limit is ever agreed, this class is the right place to apply it, and two things are
 * already in place for it: {@link RefreshTokenPersistencePort#listByFamily(String)} can count
 * the generations that exist, and the rotation below is the only place a new generation is
 * created. A policy would also need to decide what happens on reaching it, and that is not
 * obvious: refusing the refresh ends the session, while revoking the family turns a long-lived
 * login into a security incident, which is a much stronger response to an ordinary client.
 *
 * <p>Recorded as technical debt rather than fixed here, so the decision stays visible and
 * deliberate instead of appearing later as an unexplained constant.
 */
public class RefreshSessionService implements RefreshSession {

    /**
     * Lifetime given to a fresh generation. Matches the window
     * {@code CreateUserSessionService} gives the session, so a token never outlives the login
     * it belongs to.
     */
    private static final Duration TOKEN_TTL = Duration.ofDays(7);

    private final RefreshTokenPersistencePort tokenPort;
    private final UserSessionPersistencePort sessionPort;
    private final UserPersistencePort userPort;
    private final RefreshTokenHasherPort hasher;
    private final TokenGeneratorPort secrets;
    private final AuditLogPersistencePort auditLogPort;
    private final IdentifierGeneratorPort identifiers;
    private final Clock clock;

    public RefreshSessionService(RefreshTokenPersistencePort tokenPort,
                                 UserSessionPersistencePort sessionPort,
                                 UserPersistencePort userPort,
                                 RefreshTokenHasherPort hasher, TokenGeneratorPort secrets,
                                 AuditLogPersistencePort auditLogPort,
                                 IdentifierGeneratorPort identifiers, Clock clock) {
        this.tokenPort = tokenPort;
        this.sessionPort = sessionPort;
        this.userPort = userPort;
        this.hasher = hasher;
        this.secrets = secrets;
        this.auditLogPort = auditLogPort;
        this.identifiers = identifiers;
        this.clock = clock;
    }

    @Override
    public RefreshSessionResult refresh(RefreshSessionCommand command) {
        Instant now = clock.instant();
        Optional<RefreshToken> found =
                tokenPort.findByTokenHash(hasher.hash(command.rawRefreshToken()));
        if (found.isEmpty()) {
            return rejected(null);
        }
        RefreshToken presented = found.orElseThrow();

        if (presented.isReplayed()) {
            return handleReuse(presented, command, now);
        }
        if (!presented.isUsable(now)) {
            return rejected(presented.idUserSession());
        }
        Optional<UserSession> maybeSession = sessionPort.findActive(presented.idUserSession());
        if (maybeSession.isEmpty()) {
            return rejected(presented.idUserSession());
        }
        UserSession session = maybeSession.orElseThrow();
        if (!session.isActive(now)) {
            return rejected(session.idUserSession());
        }

        // The account behind the session, resolved here rather than by the caller. This is the
        // identity the replacement access token is minted from, so it can only ever be the
        // owner of the session the presented token belongs to.
        Optional<User> maybeUser = userPort.findActive(session.idUser());
        if (maybeUser.isEmpty()) {
            return rejected(session.idUserSession());
        }
        User user = maybeUser.orElseThrow();
        // A blocked or deactivated account keeps neither its access tokens nor its ability to
        // mint new ones. Without this an administrator's revocation would only stop the next
        // login while existing sessions went on renewing themselves.
        if (!user.canAuthenticate()) {
            return rejected(session.idUserSession());
        }

        // Retire the presented generation and mint its successor. Both writes and the session
        // slide share one transaction, so a failure cannot leave a rotated generation without a
        // replacement, nor two active generations in the same family.
        String rawToken = secrets.generateToken();
        Instant expiresAt = now.plus(TOKEN_TTL);
        presented.rotate(now);
        tokenPort.save(presented);
        tokenPort.save(RefreshToken.childOf(presented, identifiers.generate(),
                hasher.hash(rawToken), now, expiresAt));
        session.rotate(expiresAt, now);
        sessionPort.save(session);
        auditLogPort.save(new AuditLog(identifiers.generate(), session.idUser(),
                AuditAction.UPDATE, null, command.ipAddress(), null, now));

        return new RefreshSessionResult(RefreshStatus.ROTATED, rawToken, session.idUserSession(),
                identityOf(user));
    }

    /**
     * Projects the account into the shape the access token is minted from.
     *
     * <p>{@code lastLoginAt} is optional on the aggregate and a refresh is never the first
     * login, but it is carried as absent rather than as a fabricated instant: nothing in the
     * token depends on it, and inventing a value would put a false fact in a record.
     */
    private AuthenticatedUser identityOf(User user) {
        return new AuthenticatedUser(user.idUser(), user.idPerson(), user.email(),
                user.status(), user.lastLoginAt().orElse(null), user.profileImage().orElse(null));
    }

    private RefreshSessionResult rejected(String idUserSession) {
        return new RefreshSessionResult(RefreshStatus.REJECTED, null, idUserSession, null);
    }

    /**
     * Invalidates a family whose retired token was presented again.
     *
     * <p>Every generation of the family is revoked, which cuts off both the thief holding the
     * stolen secret and the legitimate client holding the current one. The session is revoked
     * rather than closed because this is a security event, and revocation is what records the
     * reason an operator will later read.
     *
     * <p>Generations that were already rotated keep that status. Downgrading them to revoked
     * would erase the very fact that made the replay recognisable, so a token that was spent and
     * then invalidated remains a spent token.
     *
     * @return the outcome, which never carries a new secret
     */
    private RefreshSessionResult handleReuse(RefreshToken presented, RefreshSessionCommand command,
                                             Instant now) {
        for (RefreshToken generation : tokenPort.listByFamily(presented.familyId())) {
            if (generation.status() == RefreshTokenStatus.REVOKED
                    || generation.status() == RefreshTokenStatus.ROTATED) {
                continue;
            }
            generation.revoke(now, RevocationReason.REFRESH_TOKEN_REUSE);
            tokenPort.save(generation);
        }
        Optional<UserSession> maybeSession = sessionPort.findActive(presented.idUserSession());
        maybeSession.ifPresent(session -> {
            session.revoke(now, RevocationReason.REFRESH_TOKEN_REUSE);
            sessionPort.save(session);
        });
        // audit_log.user_id references the account, not the session, so the owner is taken from
        // the session rather than from the token. A session that is already gone leaves the
        // audit entry unattributed, which the column explicitly allows.
        maybeSession.ifPresent(session -> auditLogPort.save(new AuditLog(identifiers.generate(),
                session.idUser(), AuditAction.LOGIN_FAILED, "refresh token reuse detected",
                command.ipAddress(), null, now)));
        return new RefreshSessionResult(RefreshStatus.REUSE_DETECTED, null,
                presented.idUserSession(), null);
    }
}
