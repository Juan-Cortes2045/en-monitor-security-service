package com.energymonitor.security.adapter.in.web;

import com.energymonitor.security.adapter.in.web.dto.AccountResponse;
import com.energymonitor.security.api.UserProfile;
import com.energymonitor.security.api.UserProfileQuery;
import com.energymonitor.security.adapter.in.web.dto.ApiError;
import com.energymonitor.security.adapter.in.web.dto.ChangePasswordRequest;
import com.energymonitor.security.adapter.in.web.dto.DeleteAccountRequest;
import com.energymonitor.security.adapter.in.web.dto.ForgotPasswordRequest;
import com.energymonitor.security.adapter.in.web.dto.GoogleLoginRequest;
import com.energymonitor.security.adapter.in.web.dto.LoginRequest;
import com.energymonitor.security.adapter.in.web.dto.LoginResponse;
import com.energymonitor.security.adapter.in.web.dto.LogoutRequest;
import com.energymonitor.security.adapter.in.web.dto.MessageResponse;
import com.energymonitor.security.adapter.in.web.dto.PermissionsResponse;
import com.energymonitor.security.adapter.in.web.dto.ProfileResponse;
import com.energymonitor.security.adapter.in.web.dto.RefreshRequest;
import com.energymonitor.security.adapter.in.web.dto.RefreshResponse;
import com.energymonitor.security.adapter.in.web.dto.RegisterRequest;
import com.energymonitor.security.adapter.in.web.dto.ResendVerificationRequest;
import com.energymonitor.security.adapter.in.web.dto.ResetPasswordRequest;
import com.energymonitor.security.adapter.in.web.dto.UpdateProfileRequest;
import com.energymonitor.security.adapter.in.web.dto.VerifyEmailRequest;
import com.energymonitor.security.application.command.ChangePasswordCommand;
import com.energymonitor.security.application.command.CreatePasswordResetTokenCommand;
import com.energymonitor.security.application.command.DeleteAccountCommand;
import com.energymonitor.security.application.command.RegisterUserCommand;
import com.energymonitor.security.application.command.ResetPasswordCommand;
import com.energymonitor.security.application.command.LogoutUserSessionCommand;
import com.energymonitor.security.application.command.RefreshSessionCommand;
import com.energymonitor.security.application.command.UpdateUserProfileCommand;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.ChangePassword;
import com.energymonitor.security.application.port.in.CheckPermission;
import com.energymonitor.security.application.port.in.CreatePasswordResetToken;
import com.energymonitor.security.application.port.in.DeleteAccount;
import com.energymonitor.security.application.port.in.EmailVerification;
import com.energymonitor.security.application.port.in.FindUser;
import com.energymonitor.security.application.port.in.RegisterUser;
import com.energymonitor.security.application.port.in.ResetPassword;
import com.energymonitor.security.application.port.out.ResetAttemptLimiterPort;
import com.energymonitor.security.application.port.in.LogoutUserSession;
import com.energymonitor.security.application.port.in.RefreshSession;
import com.energymonitor.security.application.port.in.UpdateUserProfile;
import com.energymonitor.security.application.result.RefreshSessionResult;
import com.energymonitor.security.domain.model.Person;
import com.energymonitor.security.infrastructure.JwtTokenIssuer;
import com.energymonitor.security.infrastructure.SecurityLoginFlow;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * HTTP adapter for authentication, sessions and password management.
 *
 * <p>The controller is a translator and nothing more. It turns a request body into an
 * application command, hands that command to an input port, and turns what comes back into a
 * response DTO. It holds no business rule: every decision belongs to a use case, and every
 * mapping is an explicit field-by-field copy, which is what keeps aggregates, password hashes
 * and persistence entities out of responses.
 *
 * <p>The account behind the authenticated endpoints is read from the validated token's
 * subject rather than from the request, so a caller can only ever act on its own account.
 *
 * <h2>Refresh and its transport</h2>
 *
 * <p>{@code POST /refresh} exchanges the secret issued at login for a new access token and a
 * new secret. The refresh token travels in the request and response bodies, matching
 * {@code LoginResponse}, and the API therefore carries no cookies and no CSRF tokens: the
 * credential is sent explicitly by the client rather than attached automatically by the
 * browser, so there is nothing for a cross-site request to ride on. The trade-off is that the
 * secret is reachable by client-side code, which makes the client's own storage discipline part
 * of the security posture. See {@code LoginResponse} for that reasoning in full.
 *
 * <h2>Known limitation of this surface</h2>
 *
 * <p>One part of the authentication flow is deliberately incomplete, recorded here so that
 * reading the code does not suggest otherwise:
 *
 * <ul>
 *   <li><strong>Password recovery cannot be completed by a real user.</strong>
 *       {@code POST /password/forgot} mints a token, stores its hash and hands the secret to
 *       {@link com.energymonitor.security.api.PasswordResetDeliveryPort}, but
 *       the only implementation shipped records the delivery instead of performing it, so
 *       {@code POST /password/reset} has no token to redeem yet. The missing piece is an
 *       outbound notification adapter, which is out of scope for this phase.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication",
        description = "Registration, sign-in, session renewal and closure, and password "
                + "management. Endpoints under this tag are stateless: no HTTP session and no "
                + "cookie is ever created, so every credential travels in the request or the "
                + "response body and the only supported authentication header is "
                + "'Authorization: Bearer <JWT>'.")
public class AuthController {

    /**
     * Only what the recovery flow needs to report. Delivery outcomes are logged by the module that
     * records them, not here.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);


    private static final String BEARER = "Bearer";

    private final RegisterUser registerUser;
    private final SecurityLoginFlow loginFlow;
    private final LogoutUserSession logoutUserSession;
    private final RefreshSession refreshSession;
    private final JwtTokenIssuer tokenIssuer;
    private final CreatePasswordResetToken createPasswordResetToken;
    private final ResetAttemptLimiterPort attemptLimiter;
    private final ThreadPoolExecutor recoveryExecutor;
    private final ResetPassword resetPassword;
    private final ChangePassword changePassword;
    private final FindUser findUser;
    private final CheckPermission checkPermission;
    private final UpdateUserProfile updateUserProfile;
    private final EmailVerification emailVerification;
    private final UserProfileQuery userProfiles;
    private final DeleteAccount deleteAccount;

    public AuthController(RegisterUser registerUser, SecurityLoginFlow loginFlow,
                          LogoutUserSession logoutUserSession, RefreshSession refreshSession,
                          JwtTokenIssuer tokenIssuer,
                          CreatePasswordResetToken createPasswordResetToken,
                          ResetAttemptLimiterPort attemptLimiter,
                          @Qualifier("passwordResetExecutor") ThreadPoolExecutor recoveryExecutor,
                          ResetPassword resetPassword, ChangePassword changePassword,
                          FindUser findUser, CheckPermission checkPermission,
                          UpdateUserProfile updateUserProfile,
                          EmailVerification emailVerification,
                          UserProfileQuery userProfiles, DeleteAccount deleteAccount) {
        this.registerUser = registerUser;
        this.loginFlow = loginFlow;
        this.logoutUserSession = logoutUserSession;
        this.refreshSession = refreshSession;
        this.tokenIssuer = tokenIssuer;
        this.createPasswordResetToken = createPasswordResetToken;
        this.attemptLimiter = attemptLimiter;
        this.recoveryExecutor = recoveryExecutor;
        this.resetPassword = resetPassword;
        this.changePassword = changePassword;
        this.findUser = findUser;
        this.checkPermission = checkPermission;
        this.updateUserProfile = updateUserProfile;
        this.emailVerification = emailVerification;
        this.userProfiles = userProfiles;
        this.deleteAccount = deleteAccount;
    }

    /**
     * Registers an account. Open by design: a caller has no identity yet.
     *
     * @param request the registration body
     * @param servlet used only for the caller's address
     * @return the created account, without its password hash
     */
    @Operation(summary = "Register an account",
            description = "Creates an account from the supplied email, password and name, and "
                    + "returns the created account without any credential field. Open by "
                    + "design: a caller has no identity yet, so there is nothing to "
                    + "authenticate.")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Account created",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = AccountResponse.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "idUser": "USR-1a2b3c4d5e",
                                      "idPerson": "PER-9f8e7d6c5b",
                                      "email": "ada@example.com",
                                      "status": "ACTIVE",
                                      "lastLogin": null,
                                      "profileImage": null
                                    }"""))),
            @ApiResponse(responseCode = "400", description = "Validation error: the body is "
                    + "missing a field or an email is malformed",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "409", description = "An account already exists for "
                    + "this email",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "422", description = "The password is well-formed but "
                    + "breaks the configured policy",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/register")
    public ResponseEntity<AccountResponse> register(@Valid @RequestBody RegisterRequest request,
                                                    HttpServletRequest servlet) {
        var account = registerUser.register(new RegisterUserCommand(request.email(),
                request.password(), request.name(), request.lastName(),
                request.profileImage(), clientIp(servlet)));
        // After the account is committed, and never able to fail the registration: a mail outage
        // must not leave a created account behind a 500. The client can ask for a new code.
        try {
            emailVerification.sendCode(account.email().value());
        } catch (RuntimeException undeliverable) {
            LOG.warn("The verification code for a new account could not be sent", undeliverable);
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(AccountResponse.from(account));
    }

    @Operation(summary = "Verify the account's email",
            description = "Checks the six-digit code sent to the address at registration and "
                    + "marks the address as verified. An unknown address and a wrong or expired "
                    + "code produce the same 400, so the endpoint cannot be used to learn which "
                    + "addresses are registered. Repeating it with a valid code is harmless.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Email verified",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class),
                            examples = @ExampleObject(value = """
                                    {"message": "Email verified."}"""))),
            @ApiResponse(responseCode = "400", description = "Validation error, or the code is "
                    + "invalid or expired",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "429", description = "Too many attempts",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/email/verify")
    public ResponseEntity<MessageResponse> verifyEmail(
            @Valid @RequestBody VerifyEmailRequest request, HttpServletRequest servlet) {
        attemptLimiter.checkAllowed(clientIp(servlet));
        emailVerification.verify(request.email(), request.code());
        return ResponseEntity.ok(new MessageResponse("Email verified."));
    }

    @Operation(summary = "Send a new verification code",
            description = "Sends the current verification code again. Always answers 202 with "
                    + "an empty body, whether or not the address is registered or already "
                    + "verified, for the same reason as the password-recovery request.")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Request accepted, empty body",
                    content = @Content),
            @ApiResponse(responseCode = "400", description = "Validation error: the body "
                    + "carries no email",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/email/verification/resend")
    public ResponseEntity<Void> resendVerification(
            @Valid @RequestBody ResendVerificationRequest request, HttpServletRequest servlet) {
        attemptLimiter.checkAllowed(clientIp(servlet));
        // Off the request thread, like the recovery request, so the answer time does not depend on
        // whether the address exists.
        try {
            recoveryExecutor.execute(() -> {
                try {
                    emailVerification.sendCode(request.email());
                } catch (RuntimeException failure) {
                    LOG.warn("A verification resend could not be processed", failure);
                }
            });
        } catch (RejectedExecutionException queueFull) {
            LOG.warn("The recovery queue is full; a verification resend was not processed");
        }
        return ResponseEntity.accepted().build();
    }

    /**
     * Authenticates and issues an access token plus a refresh session.
     *
     * <p>Every rejection produces the same 401 with the same body. The use case records the
     * precise reason in the typed error trail, but telling the caller whether the address is
     * unknown or the password wrong would turn this endpoint into an account-enumeration
     * oracle, so that distinction stops at the server and the failure is re-thrown as an
     * {@link AuthenticationRejectedException} for the shared handler to render.
     *
     * @param request the credentials
     * @param servlet used for the caller's address and user agent
     * @return the tokens and account
     */
    @Operation(summary = "Sign in",
            description = "Authenticates an email and password and returns a signed JWT access "
                    + "token together with an opaque refresh token. Every rejection produces "
                    + "the same 401 with the same body on purpose: telling the caller whether "
                    + "the address is unknown or the password wrong would turn this endpoint "
                    + "into an account-enumeration oracle.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Authenticated; tokens issued",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = LoginResponse.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "accessToken": "eyJhbGciOiJSUzI1NiJ9...",
                                      "refreshToken": "3f8c1d4e7a0b52c9...",
                                      "tokenType": "Bearer",
                                      "expiresIn": 900,
                                      "account": {
                                        "idUser": "USR-1a2b3c4d5e",
                                        "idPerson": "PER-9f8e7d6c5b",
                                        "email": "ada@example.com",
                                        "status": "ACTIVE",
                                        "lastLogin": "2026-10-05T14:31:00Z",
                                        "profileImage": null
                                      }
                                    }"""))),
            @ApiResponse(responseCode = "400", description = "Validation error: the body is "
                    + "missing an email or a password",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "Authentication rejected: unknown "
                    + "address or wrong password, indistinguishable to the caller",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "The account exists but is blocked "
                    + "or inactive, so no session may be opened",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request,
                                               HttpServletRequest servlet) {
        SecurityLoginFlow.LoginOutcome login = loginFlow.login(request.email(), request.password(),
                clientIp(servlet), servlet.getHeader("User-Agent"))
                .orElseThrow(AuthenticationRejectedException::new);
        return ResponseEntity.ok(new LoginResponse(login.accessToken(), login.refreshToken(),
                BEARER, login.expiresInSeconds(), AccountResponse.from(login.account())));
    }

    @Operation(summary = "Sign in with Google",
            description = "Exchanges the authorization code of Google's sign-in popup for the "
                    + "usual credentials. The first time it creates the account with the name, "
                    + "last name, photo and address of the Google account. An address that "
                    + "belongs to an account registered with a password is refused with 409.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Signed in",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = LoginResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid or expired code, or an "
                    + "address Google did not verify",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "The account is blocked or inactive",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "409", description = "The address belongs to an account "
                    + "registered with a password",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "503", description = "Google sign-in is not configured",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/google")
    public ResponseEntity<LoginResponse> loginWithGoogle(@Valid @RequestBody GoogleLoginRequest request,
                                                         HttpServletRequest servlet) {
        SecurityLoginFlow.LoginOutcome login = loginFlow.loginWithGoogle(request.code(),
                clientIp(servlet), servlet.getHeader("User-Agent"))
                .orElseThrow(AuthenticationRejectedException::new);
        return ResponseEntity.ok(new LoginResponse(login.accessToken(), login.refreshToken(),
                BEARER, login.expiresInSeconds(), AccountResponse.from(login.account())));
    }

    /**
     * Exchanges a refresh token for a new pair of credentials.
     *
     * <p>Reachable without an access token, which is the whole point: this is what a client
     * calls once its access token has expired, so requiring one would make it useless exactly
     * when it is needed.
     *
     * <p>The controller does no refresh-token work of its own. It does not look up a
     * generation, compute a digest, walk a family or decide whether a token was replayed; all
     * of that belongs to {@link RefreshSession}, and the identity used to sign the new access
     * token comes back from that use case rather than from a lookup here. That is what makes
     * the endpoint unable to be pointed at somebody else's account.
     *
     * <p>Every failure leaves as the same 401 with the same body. An unknown, expired or revoked
     * secret and a detected replay are different situations internally, and the difference is
     * written to the audit trail, but a client learns only that the authentication failed.
     * Distinguishing them in the response would tell an attacker which tokens are worth
     * replaying.
     *
     * @param request the presented secret
     * @param servlet used for the caller's address
     * @return the renewed credentials
     */
    @Operation(summary = "Renew credentials",
            description = "Exchanges a refresh token for a new access token and a new refresh "
                    + "token, rotating the session. Reachable without an access token, which is "
                    + "the whole point: this is what a client calls once its access token has "
                    + "expired. Every failure leaves as the same 401 with the same body, so a "
                    + "client cannot use it to learn which tokens are worth replaying.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Credentials renewed and the "
                    + "refresh token rotated",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = RefreshResponse.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "accessToken": "eyJhbGciOiJSUzI1NiJ9...",
                                      "refreshToken": "8b2e6f1a3c5d4907..."
                                    }"""))),
            @ApiResponse(responseCode = "400", description = "Validation error: the body "
                    + "carries no refresh token",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "The refresh token is unknown, "
                    + "expired, revoked or replayed",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(@Valid @RequestBody RefreshRequest request,
                                                    HttpServletRequest servlet) {
        RefreshSessionResult result = refreshSession.refresh(
                new RefreshSessionCommand(request.refreshToken(), clientIp(servlet)));
        if (!result.issued()) {
            throw new AuthenticationRejectedException();
        }
        return ResponseEntity.ok(new RefreshResponse(
                tokenIssuer.issue(result.identity()), result.rawRefreshToken()));
    }

    /**
     * Logs out of a session. Requires a valid access token.
     *
     * <p>The session is closed, not revoked. Walking away is not a security event, and the row
     * stays readable as an ordinary departure rather than as a suspected compromise.
     *
     * @param request       names the session to close
     * @param authentication the validated caller, whose subject is the account identifier
     * @param servlet       used for the caller's address
     * @return an acknowledgement
     */
    @Operation(summary = "Sign out",
            description = "Closes the named session. The session is closed, not revoked: "
                    + "walking away is not a security event. The session identifier is read "
                    + "from the access token's subject, so a caller can only close its own "
                    + "session.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Session closed",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class),
                            examples = @ExampleObject(value = """
                                    {"message": "Session closed."}"""))),
            @ApiResponse(responseCode = "400", description = "Validation error: the body "
                    + "carries no session identifier",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "Missing, malformed or expired "
                    + "access token",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "404", description = "No active session with that "
                    + "identifier",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(@Valid @RequestBody LogoutRequest request,
                                                  Authentication authentication,
                                                  HttpServletRequest servlet) {
        logoutUserSession.logout(new LogoutUserSessionCommand(request.idUserSession(),
                authentication.getName(), clientIp(servlet)));
        return ResponseEntity.ok(new MessageResponse("Session closed."));
    }

    /**
     * Requests a password reset.
     *
     * <p>What this endpoint does: looks the account up, mints a reset token, hashes it, stores
     * the hash, and answers 202. The response carries no body at all - not a message, and
     * certainly not the token.
     *
     * <p>Silence is the point. An acknowledgement whose wording is the same for every caller
     * says nothing about whether the address is registered, and an empty body says even less
     * than a fixed sentence could. What the caller learns is that the request was received,
     * which is all the endpoint is ever allowed to tell them.
     *
     * <p>The token never comes back here. Returning it would hand a working credential to
     * whoever asked and turn this endpoint into an account-takeover primitive. It leaves the
     * server through {@link com.energymonitor.security.api.PasswordResetDeliveryPort}
     * instead, an outbound channel the use case hands the secret to, and the database keeps
     * only its hash. The controller never sees the secret at all: the use case's return value is
     * discarded rather than translated into a DTO.
     *
     * <p>The delivery itself is not built yet: the shipped
     * {@link com.energymonitor.security.api.PasswordResetDeliveryPort}
     * implementation records the attempt instead of sending anything, so the handler is complete
     * while the recovery flow is not. Making the flow work means implementing that port against
     * the deployment's mail, SMS or push infrastructure; it does not mean changing this handler,
     * and it must not mean echoing the token to get around the missing channel.
     *
     * @param request the account address
     * @return 202 with an empty body, whether or not the account exists
     */
    @Operation(summary = "Request a password reset",
            description = "Looks the account up, mints a reset token, hashes it, stores the "
                    + "hash and hands the secret to the configured delivery channel. Always "
                    + "answers 202 with no body at all - not a message, and never the token - "
                    + "whether or not the account exists, because an acknowledgement whose "
                    + "wording varies would reveal which addresses are registered.")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Request accepted, empty body",
                    content = @Content),
            @ApiResponse(responseCode = "400", description = "Validation error: the body "
                    + "carries no email",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/password/forgot")
    public ResponseEntity<Void> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request, HttpServletRequest servlet) {
        String caller = clientIp(servlet);

        // Charged here, on the request thread, before anything opens a transaction or takes a
        // connection. The limiter keeps its counters in memory, so a caller that has spent its
        // allowance is turned away without ever reaching the database.
        attemptLimiter.checkAllowed(caller);

        // The whole flow leaves the request thread: resolving the account, minting the code and
        // writing its delivery record. What the caller is told must not depend on any of that, and
        // measuring it showed a request for a registered address answered in about 70 ms against
        // about 24 ms for an unregistered one, which is enough to tell them apart. Answering before
        // any of it runs removes the difference by construction rather than by padding.
        try {
            recoveryExecutor.execute(() -> issueCodeQuietly(request.email()));
        } catch (RejectedExecutionException queueFull) {
            // Still 202. The endpoint acknowledges every request identically whether or not the
            // account exists, so a full queue must not become a way to tell a registered address
            // from an unregistered one either.
            LOG.warn("The recovery queue is full; a recovery request was not processed");
        }
        return ResponseEntity.accepted().build();
    }

    /**
     * Issues a recovery code, reporting nothing about whether the account exists.
     *
     * <p>Runs off the request thread, so there is no caller left to leak anything to. The answer the
     * request received was already sent.
     *
     * @param email the address the code was asked for
     */
    private void issueCodeQuietly(String email) {
        try {
            createPasswordResetToken.create(new CreatePasswordResetTokenCommand(email));
        } catch (UserNotFoundException unknownAccount) {
            // Swallowed on purpose: reporting it would reveal which addresses are registered.
            LOG.debug("A recovery request named an account that does not exist");
        } catch (RuntimeException failure) {
            // Nothing above this point can turn a failed request into an error response, because the
            // response was already sent. Logged so an operator can see the flow broke.
            LOG.warn("A recovery request could not be processed", failure);
        }
    }

    /**
     * Completes a password reset with a token obtained through the reset channel.
     *
     * <p>This endpoint works: it hashes the presented token, looks the hash up, rejects it when
     * it is unknown, expired or already used, checks the replacement against the configured
     * policy, and commits the new hash, the token consumption and the audit row in one
     * transaction.
     *
     * <p>It is reachable only by a caller who already holds a valid token, and today no such
     * token can reach a user, because {@code POST /password/forgot} has no delivery channel
     * (see that method). The endpoint being public is therefore necessary but not yet
     * sufficient for the recovery flow to work end to end; the missing piece is token
     * delivery, not this handler.
     *
     * <p>The token is accepted here because completing a reset is the entire purpose of the
     * request. It is hashed before anything else touches it and is never echoed in the response.
     *
     * @param request the token and the replacement password
     * @param servlet used for the caller's address
     * @return an acknowledgement
     */
    @Operation(summary = "Complete a password reset",
            description = "Hashes the presented reset token, looks the hash up, rejects it when "
                    + "it is unknown, expired or already used, checks the replacement against "
                    + "the configured policy, and commits the new hash, the token consumption "
                    + "and the audit row in one transaction. The token itself is accepted "
                    + "because redeeming it is the purpose of the request, and it is never "
                    + "echoed in the response. Open by design: the reset token is the "
                    + "credential, so no access token is required.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Password replaced",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class),
                            examples = @ExampleObject(value = """
                                    {"message": "Password updated."}"""))),
            @ApiResponse(responseCode = "400", description = "Validation error, or the reset "
                    + "token is unknown, expired or already used",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "422", description = "The new password is well-formed "
                    + "but breaks the configured policy",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/password/reset")
    public ResponseEntity<MessageResponse> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request, HttpServletRequest servlet) {
        // Outside the transactional proxy on purpose. Everything the use case does happens inside a
        // transaction, which means a connection is already held by the time its first statement
        // runs; charging the limit inside would be too late to spare a caller the connection it is
        // refusing. The limiter keeps its counters in memory, so it answers without touching the
        // database at all.
        attemptLimiter.checkAllowed(clientIp(servlet));

        resetPassword.reset(new ResetPasswordCommand(request.email(), request.resetToken(),
                request.newPassword(), clientIp(servlet)));
        return ResponseEntity.ok(new MessageResponse("Password updated."));
    }

    /**
     * Changes the caller's own password. Requires a valid access token.
     *
     * @param request       the current and replacement passwords
     * @param authentication the validated caller
     * @param servlet       used for the caller's address
     * @return an acknowledgement
     */
    @Operation(summary = "Change the caller's own password",
            description = "Checks the current password and replaces it with a new one that "
                    + "satisfies the configured policy. The account is read from the access "
                    + "token's subject rather than from the request, so a caller can only ever "
                    + "change its own password.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Password replaced",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class),
                            examples = @ExampleObject(value = """
                                    {"message": "Password changed."}"""))),
            @ApiResponse(responseCode = "400", description = "Validation error: a password is "
                    + "missing or blank",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "Missing, malformed or expired "
                    + "access token, or the current password is not correct",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "The account is blocked or "
                    + "inactive",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "422", description = "The new password is well-formed "
                    + "but breaks the configured policy",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/password/change")
    public ResponseEntity<MessageResponse> changePassword(
            @Valid @RequestBody ChangePasswordRequest request, Authentication authentication,
            HttpServletRequest servlet) {
        changePassword.change(new ChangePasswordCommand(authentication.getName(),
                request.currentPassword(), request.newPassword(), clientIp(servlet)));
        return ResponseEntity.ok(new MessageResponse("Password changed."));
    }

    /**
     * Edits the caller's own profile. Requires a valid access token.
     *
     * <p><strong>The identity cannot be chosen by the caller.</strong> There is no
     * {@code idUser} here, no path variable and no query parameter: the account comes from the
     * validated token's subject, the same as in {@code GET /account} and
     * {@code POST /password/change}. There is therefore nothing to validate and nothing to
     * compare, and no request body can move the edit onto another account - the endpoint has no
     * input through which such an attempt could be expressed. A caller that tries anyway by
     * sending an {@code idUser} in the body has it ignored as an unknown property, exactly as an
     * old client sending the removed {@code phone} field does.
     *
     * <p><strong>What the response reports.</strong> The 200 body is the person as it now stands
     * in the database, read back from the aggregate the use case saved rather than echoed from
     * the request. That is the point of the response existing: it distinguishes a rename that
     * was written from one that was merely accepted. The account half of the request, the new
     * address and the avatar, is committed in the same transaction but is not echoed here; it is
     * read from {@code GET /api/v1/auth/account}.
     *
     * <p><strong>Partial updates, and the name as a pair.</strong> Every field is optional and an
     * absent one is left untouched. The name is the exception worth stating plainly: a person
     * is required to have both a first name and a last name (INV-001) and the aggregate replaces
     * them together, so sending one of the two leaves both of them unchanged. A client renames by
     * sending both.
     *
     * <p><strong>No phone number is accepted, stored or returned.</strong> Notifications are
     * email only, so the field was removed from the domain, from the {@code person} table and
     * from this contract before the endpoint existed. A body that still carries it is not
     * rejected, so clients written against the older contract keep working; nothing is persisted
     * from it. Re-adding the field is a schema change, not an edit to this method, and the
     * request record is shaped so that it cannot be reintroduced by accident.
     *
     * <p><strong>Statuses that really occur.</strong> 200 with the stored profile. 400 for a body
     * that is absent, unparseable or fails bean validation, including a name too long for its
     * column and a malformed new address. 401 for a missing, malformed or expired token, decided
     * by the filter chain before this method runs. 404 when the token is valid but the account,
     * or the person it points at, has been soft-deleted: the use case reports it and the shared
     * handler renders it in the {@link ApiError} shape. 409 when the new address already belongs
     * to another account.
     *
     * <p>There is no 403. A blocked or inactive account is refused at sign-in, but an access
     * token already issued for one is still valid, and this use case asks for an account that is
     * not soft-deleted rather than for one that can sign in; documenting a 403 here would
     * promise a check this path does not make.
     *
     * <p>The route answers 405 for any other verb, since a POST would leave what "replace the
     * profile" means undefined; the shared handler renders it and publishes the allowed methods
     * in the {@code Allow} header.
     *
     * @param request       the fields to change
     * @param authentication the validated caller, whose subject is the account identifier
     * @param servlet       used for the caller's address
     * @return the stored profile
     */
    @Operation(summary = "Update the caller's own profile",
            description = "Edits the name, the account address and the avatar of the "
                    + "authenticated caller. Every field is optional and an absent one is left "
                    + "unchanged; the name is replaced as a pair, since a person must have both "
                    + "a first name and a last name. The identity is taken from the access "
                    + "token's subject rather than from any request field, so a caller can only "
                    + "edit its own profile and no body can point the edit at another account. "
                    + "The response is the profile as stored, so a client can tell a rename that "
                    + "was written from one that was merely accepted. No phone number is "
                    + "accepted: the field was removed from the model and from this contract "
                    + "because notifications are email only, and a body still carrying it is "
                    + "ignored rather than rejected, so older clients keep working.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profile updated; the stored "
                    + "person is returned",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ProfileResponse.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "idPerson": "PER-9f8e7d6c5b",
                                      "name": "Grace",
                                      "lastName": "Hopper"
                                    }"""))),
            @ApiResponse(responseCode = "400", description = "Validation error: the body is "
                    + "absent, unparseable, carries a name longer than its column or a malformed "
                    + "new address",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "Missing, malformed or expired "
                    + "access token",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "404", description = "The token is valid but the "
                    + "account, or the person it points at, has been deleted",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "409", description = "The requested new address already "
                    + "belongs to another account",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "405", description = "The route exists but not for "
                    + "this verb; the profile is replaced, so only PUT edits it and the allowed "
                    + "methods come back in the Allow header",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @PutMapping("/profile")
    public ResponseEntity<ProfileResponse> updateProfile(
            @Valid @RequestBody UpdateProfileRequest request, Authentication authentication,
            HttpServletRequest servlet) {
        Person updated = updateUserProfile.update(new UpdateUserProfileCommand(
                authentication.getName(), request.name(), request.lastName(),
                request.profileImage(), request.newEmail(), clientIp(servlet)));
        return ResponseEntity.ok(ProfileResponse.from(updated));
    }

    @Operation(summary = "Delete the caller's own account",
            description = "Confirms the current password, then soft-deletes the account and its "
                    + "person (deleted_at), closes its sessions and drops its home memberships. "
                    + "A home the caller is the only member of is deleted with it. Refused with 409 "
                    + "while the caller is the only owner of a home that still has other "
                    + "members. The account is read from the access token's subject, so a "
                    + "caller can only delete itself.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Account deleted", content = @Content),
            @ApiResponse(responseCode = "400", description = "Validation error: the password "
                    + "is missing",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "Missing, malformed or expired "
                    + "access token, or the password is not correct",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "409", description = "The caller is the only owner of a "
                    + "home that still has other members",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/account/delete")
    public ResponseEntity<Void> deleteAccount(@Valid @RequestBody DeleteAccountRequest request,
                                              Authentication authentication,
                                              HttpServletRequest servlet) {
        deleteAccount.delete(new DeleteAccountCommand(authentication.getName(), request.password(),
                clientIp(servlet)));
        return ResponseEntity.noContent().build();
    }

    /**
     * Returns the account details for the authenticated caller. The identity comes from the
     * access token, not from a request parameter.
     *
     * @param authentication the validated caller
     * @return the account representation
     */
    @Operation(summary = "Get the authenticated account",
            description = "Returns the account of the caller, taken from the access token's "
                    + "subject rather than from any request parameter. The response never "
                    + "contains the password hash or any session or persistence detail.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Account found",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = AccountResponse.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "idUser": "USR-1a2b3c4d5e",
                                      "idPerson": "PER-9f8e7d6c5b",
                                      "email": "ada@example.com",
                                      "status": "ACTIVE",
                                      "lastLogin": "2026-10-05T14:31:00Z",
                                      "profileImage": null,
                                      "name": "Ada",
                                      "lastName": "Lovelace"
                                    }"""))),
            @ApiResponse(responseCode = "401", description = "Missing, malformed or expired "
                    + "access token",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "404", description = "The token is valid but names an "
                    + "account that no longer exists; empty body",
                    content = @Content)
    })
    @GetMapping("/account")
    public ResponseEntity<AccountResponse> getAccount(Authentication authentication) {
        return findUser.findByIdentifier(authentication.getName())
                .map(user -> {
                    UserProfile profile = userProfiles.findByIds(java.util.List.of(user.idUser()))
                            .get(user.idUser());
                    return profile == null ? AccountResponse.from(user)
                            : AccountResponse.from(user, profile.name(), profile.lastName());
                })
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Returns the permission codes the authenticated caller holds.
     *
     * <p><strong>Why the whole set in one call.</strong> This is the endpoint a client calls once
     * after sign-in to decide what to render: which menu entries exist, which routes are guarded,
     * which buttons are enabled. A per-code {@code ?code=…} variant would answer a question the
     * client cannot even pose, because it holds only an access token and no catalogue of the codes
     * the server knows; it would force one round trip per candidate code and still leave "what can
     * this account do" unanswerable. So the resource is a collection, returned once, as codes
     * rather than identifiers because the code is the stable contract (INV-022). See
     * {@link PermissionsResponse} for the full argument.
     *
     * <p><strong>Why the identity cannot be a parameter.</strong> There is no {@code idUser}, no
     * path variable and no query parameter here: the subject of the validated token is the only
     * input to the use case, exactly as in {@code GET /account} and
     * {@code POST /password/change}. A caller therefore cannot ask what somebody else may do, and
     * adding an optional identity parameter later would be an insecure-by-construction change
     * rather than a compatible one.
     *
     * <p><strong>Nothing is decided here.</strong> The controller holds no catalogue of codes and
     * performs no comparison: it asks {@link CheckPermission} for the codes the account holds and
     * publishes them. The RBAC walk, the enabled-role filtering and the code-to-permission
     * resolution belong to the use case, which resolves the same chain whether it is answering this
     * question or a single-code check, so the two can never disagree.
     *
     * <p><strong>Statuses that really occur.</strong> 200 with the list, empty when the account
     * holds nothing or cannot authenticate - an authenticated caller entitled to nothing is not an
     * error, and answering with an empty list rather than 403 keeps the client on the same code
     * path it already has for a user with no roles. 401 when the token is missing, malformed or
     * expired, which the filter chain decides before this method runs. 404 when the token is valid
     * but names an account that is gone: the use case reports it and the shared handler renders it
     * in the {@link ApiError} shape. There is no 400 because the endpoint takes no body and no
     * parameter, so there is nothing a client can get wrong.
     *
     * @param authentication the validated caller, whose subject is the account identifier
     * @return the granted permission codes
     */
    @Operation(summary = "List the caller's permission codes",
            description = "Returns every permission code the caller currently holds, resolved "
                    + "through the enabled roles assigned to the account. The identity is taken "
                    + "from the access token's subject rather than from any request parameter, so "
                    + "a caller can only ask about itself. The list is sorted and free of "
                    + "duplicates, and is empty rather than an error when the account holds no "
                    + "permission or cannot authenticate.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Codes resolved; the list is empty "
                    + "when the caller holds no permission",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = PermissionsResponse.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "permissions": ["ALERT.READ", "METER.READ"]
                                    }"""))),
            @ApiResponse(responseCode = "401", description = "Missing, malformed or expired "
                    + "access token",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "404", description = "The token is valid but names an "
                    + "account that no longer exists",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @GetMapping("/permissions")
    public ResponseEntity<PermissionsResponse> getPermissions(Authentication authentication) {
        return ResponseEntity.ok(PermissionsResponse.of(
                checkPermission.listGrantedCodes(authentication.getName())));
    }

    /**
     * The address the connection actually came from.
     *
     * <p><strong>{@code X-Forwarded-For} is deliberately ignored.</strong> It used to be read
     * here, which meant the value recorded in the audit trail, and fed to the password-recovery
     * attempt limiter, was whatever the caller put in a request header. Any client could therefore
     * choose its own recorded address, and a limiter keyed on it could be sidestepped by sending a
     * different value per request. A header is only trustworthy when something has already
     * established which peers are allowed to set it, and nothing here does.
     *
     * <p>Behind a reverse proxy this records the proxy's address rather than the caller's, and
     * that has a consequence worth stating: every request then shares one attempt allowance, so
     * the password-recovery rate limit becomes the limit for all users together. A deployment in
     * that position must configure the container's own trusted-proxy handling, which rewrites
     * {@link HttpServletRequest#getRemoteAddr()} from the validated header
     * ({@code server.forward-headers-strategy=native}). Doing it there rather than here is the
     * point: the trust decision belongs to the deployment's configuration, not to a method that
     * cannot know who is in front of it.
     *
     * @param servlet the current request
     * @return the remote address, or {@code null} if the container reports none
     */
    private String clientIp(HttpServletRequest servlet) {
        return servlet.getRemoteAddr();
    }
}
