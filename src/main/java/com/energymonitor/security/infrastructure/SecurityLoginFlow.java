package com.energymonitor.security.infrastructure;

import com.energymonitor.security.application.exception.GoogleSignInUnavailableException;
import com.energymonitor.security.application.port.in.SignInWithGoogle;
import com.energymonitor.security.application.port.out.GoogleIdentityPort;
import com.energymonitor.security.application.command.AuthenticateUserCommand;
import com.energymonitor.security.application.command.CreateUserSessionCommand;
import com.energymonitor.security.application.port.in.AuthenticateUser;
import com.energymonitor.security.application.port.in.CreateUserSession;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.RefreshTokenHasherPort;
import com.energymonitor.security.application.port.out.RefreshTokenPersistencePort;
import com.energymonitor.security.application.port.out.TokenGeneratorPort;
import com.energymonitor.security.application.result.AuthenticatedUser;
import com.energymonitor.security.domain.model.RefreshToken;
import com.energymonitor.security.domain.model.UserSession;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Orchestrates the login exchange: authenticate, open a session, issue an access token.
 *
 * <p>The three steps are ordered by meaning rather than by convenience, and none of them
 * contains business logic of its own, so none of it belongs in a controller:
 *
 * <ol>
 *   <li>{@link AuthenticateUser} classifies the attempt and, on success, returns a
 *       credential-free {@link AuthenticatedUser}.</li>
 *   <li>{@link CreateUserSession} opens the refresh-token session for that account.</li>
 *   <li>{@link JwtTokenIssuer} signs the short-lived access token.</li>
 * </ol>
 *
 * <p>A rejected attempt stops at the first step, so it never creates a session row and never
 * mints a token. The rejection comes back as an empty {@link Optional} and the delivery layer
 * decides how to present it, which keeps the account-enumeration policy out of this class.
 */
@Component
public class SecurityLoginFlow {

    /** Matches the session window set by {@code CreateUserSessionService}. */
    private static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(7);

    private final AuthenticateUser authenticateUser;
    private final CreateUserSession createUserSession;
    private final RefreshTokenPersistencePort refreshTokens;
    private final RefreshTokenHasherPort hasher;
    private final TokenGeneratorPort tokenGenerator;
    private final IdentifierGeneratorPort identifiers;
    private final JwtTokenIssuer tokenIssuer;
    private final Clock clock;
    private final GoogleIdentityPort google;
    private final SignInWithGoogle signInWithGoogle;

    public SecurityLoginFlow(AuthenticateUser authenticateUser, CreateUserSession createUserSession,
                             RefreshTokenPersistencePort refreshTokens, RefreshTokenHasherPort hasher,
                             TokenGeneratorPort tokenGenerator, IdentifierGeneratorPort identifiers,
                             JwtTokenIssuer tokenIssuer, Clock clock, GoogleIdentityPort google,
                             SignInWithGoogle signInWithGoogle) {
        this.google = google;
        this.signInWithGoogle = signInWithGoogle;
        this.authenticateUser = authenticateUser;
        this.createUserSession = createUserSession;
        this.refreshTokens = refreshTokens;
        this.hasher = hasher;
        this.tokenGenerator = tokenGenerator;
        this.identifiers = identifiers;
        this.tokenIssuer = tokenIssuer;
        this.clock = clock;
    }

    /**
     * What a successful login yields.
     *
     * @param accessToken      the signed JWT the client sends as a bearer token
     * @param refreshToken     the opaque session token, currently returned in the login
     *                         response body rather than in an HttpOnly cookie. There is no
     *                         {@code /auth/refresh} endpoint yet, so nothing currently renews
     *                         an access token with it; see {@code LoginResponse} for the
     *                         transport decision left open for the refresh flow.
     * @param expiresInSeconds access token lifetime, so the client knows when to refresh
     * @param account          the authenticated identity
     */
    public record LoginOutcome(String accessToken, String refreshToken, long expiresInSeconds,
                               AuthenticatedUser account) {
    }

    /**
     * Authenticates and, when the attempt succeeds, opens a session and issues a token.
     *
     * @param email       the account address
     * @param rawPassword the plain-text candidate, never stored or logged
     * @param ipAddress   the caller's address, recorded in the audit or error trail
     * @param userAgent   the caller's user agent, stored with the session
     * @return the issued credentials, or empty when the attempt was rejected
     */
    public Optional<LoginOutcome> login(String email, String rawPassword, String ipAddress,
                                        String userAgent) {
        var result = authenticateUser.authenticate(
                new AuthenticateUserCommand(email, rawPassword, ipAddress));
        if (!result.isSuccess()) {
            return Optional.empty();
        }
        return Optional.of(open(result.user().orElseThrow(), ipAddress, userAgent));
    }

    /**
     * Signs in with the authorization code of Google's popup, creating the account the first
     * time. The call to Google happens before, and outside, the transaction of the use case.
     *
     * @return empty when the code is invalid or Google did not verify the address
     * @throws GoogleSignInUnavailableException when no Google client is configured
     */
    public Optional<LoginOutcome> loginWithGoogle(String authorizationCode, String ipAddress,
                                                  String userAgent) {
        if (!google.isConfigured()) {
            throw new GoogleSignInUnavailableException("Google sign-in is not configured");
        }
        return google.exchange(authorizationCode)
                .flatMap(identity -> signInWithGoogle.signIn(identity, ipAddress))
                .map(identity -> open(identity, ipAddress, userAgent));
    }

    private LoginOutcome open(AuthenticatedUser identity, String ipAddress, String userAgent) {
        UserSession session = createUserSession.create(
                new CreateUserSessionCommand(identity.idUser(), ipAddress, userAgent));

        // The session is a login and the token is a secret hanging off it, so the first
        // generation is issued here rather than inside the session use case. The raw token
        // exists only in this frame: it is hashed on the way in and returned on the way out.
        Instant now = clock.instant();
        String rawToken = tokenGenerator.generateToken();
        String idRefreshToken = identifiers.generate();
        refreshTokens.save(RefreshToken.root(idRefreshToken, session.idUserSession(),
                hasher.hash(rawToken), now, now.plus(REFRESH_TOKEN_TTL)));

        return new LoginOutcome(tokenIssuer.issue(identity), rawToken,
                tokenIssuer.accessTokenTtl().toSeconds(), identity);
    }
}
