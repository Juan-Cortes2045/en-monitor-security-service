package com.energymonitor.security.adapter.in.web;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.mockito.ArgumentCaptor;

import com.energymonitor.security.application.command.RegisterUserCommand;
import com.energymonitor.security.application.command.ResetPasswordCommand;
import com.energymonitor.security.application.exception.EmailAlreadyRegisteredException;
import com.energymonitor.security.application.exception.InvalidVerificationCodeException;
import com.energymonitor.security.application.exception.PasswordPolicyViolationException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.ChangePassword;
import com.energymonitor.security.application.port.in.CheckPermission;
import com.energymonitor.security.application.port.in.CreatePasswordResetToken;
import com.energymonitor.security.application.port.in.EmailVerification;
import com.energymonitor.security.application.port.in.FindUser;
import com.energymonitor.security.application.port.in.DeleteAccount;
import com.energymonitor.security.application.command.DeleteAccountCommand;
import com.energymonitor.security.application.exception.CurrentPasswordMismatchException;
import com.energymonitor.security.api.UserProfile;
import com.energymonitor.security.api.UserProfileQuery;
import com.energymonitor.security.application.port.in.LogoutUserSession;
import com.energymonitor.security.application.port.in.RefreshSession;
import com.energymonitor.security.application.port.in.RegisterUser;
import com.energymonitor.security.application.port.in.ResetPassword;
import com.energymonitor.security.application.port.in.UpdateUserProfile;
import com.energymonitor.security.application.result.AuthenticatedUser;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PasswordHash;
import com.energymonitor.security.domain.model.Person;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserStatus;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import com.energymonitor.security.infrastructure.JwtTokenIssuer;
import com.energymonitor.security.infrastructure.SecurityLoginFlow;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * The HTTP contract of the Security API: status codes, error shape and route protection.
 *
 * <p>The input ports are replaced so the assertions are about the delivery layer only. The
 * security filter chain, the JWT encoder and decoder, the exception handler and the JSON
 * mapping are all the real ones, so a token minted here is validated by the same code that
 * guards production traffic.
 */
@SpringBootTest
@org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
class AuthControllerWebTest extends JwtKeyedTest {

    private static final String EMAIL = "someone@example.com";
    private static final String PASSWORD = "StrongPass1!";
    private static final Instant REGISTRATION = Instant.parse("2026-01-02T03:04:05Z");

    @Autowired
    private MockMvc mvc;

    @Autowired
    private JwtTokenIssuer tokenIssuer;

    /** Reads the published description. Not a bean: nothing in the application needs one. */
    private final ObjectMapper json = new ObjectMapper();

    @MockitoBean
    private RegisterUser registerUser;

    @MockitoBean
    private SecurityLoginFlow loginFlow;

    @MockitoBean
    private LogoutUserSession logoutUserSession;

    @MockitoBean
    private CreatePasswordResetToken createPasswordResetToken;

    @MockitoBean
    private ResetPassword resetPassword;

    @MockitoBean
    private ChangePassword changePassword;

    @MockitoBean
    private RefreshSession refreshSession;

    @MockitoBean
    private CheckPermission checkPermission;

    @MockitoBean
    private UpdateUserProfile updateUserProfile;

    @MockitoBean
    private EmailVerification emailVerification;

    @MockitoBean
    private FindUser findUser;

    @MockitoBean
    private UserProfileQuery userProfileQuery;

    @MockitoBean
    private DeleteAccount deleteAccount;

    private static User newAccount() {
        return User.register("USR0000001", "PER0000001", PasswordHash.of("$2a$10$abcdefghij"),
                Email.of(EMAIL), REGISTRATION, null);
    }

    private static AuthenticatedUser identity() {
        return new AuthenticatedUser("USR0000001", "PER0000001", Email.of(EMAIL),
                UserStatus.ACTIVE, Instant.now(), null);
    }

    private static String registrationBody() {
        return """
                {"email":"someone@example.com","password":"StrongPass1!","name":"Ada",
                 "lastName":"Lovelace",
                 "profileImage":"https://example.com/a.png"}
                """;
    }

    private String bearerFor(AuthenticatedUser identity) {
        return "Bearer " + tokenIssuer.issue(identity);
    }

    // ---------------------------------------------------------------- registration

    @Test
    void registersAnAccountAndAnswers201() throws Exception {
        given(registerUser.register(any())).willReturn(newAccount());

        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationBody()))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.idUser").value("USR0000001"))
                .andExpect(jsonPath("$.idPerson").value("PER0000001"))
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    void sendsTheVerificationCodeOnceTheAccountIsCreated() throws Exception {
        given(registerUser.register(any())).willReturn(newAccount());

        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationBody()))
                .andExpect(status().isCreated());

        verify(emailVerification).sendCode(EMAIL);
    }

    @Test
    void stillAnswers201WhenTheVerificationCodeCannotBeSent() throws Exception {
        given(registerUser.register(any())).willReturn(newAccount());
        willThrow(new IllegalStateException("smtp down")).given(emailVerification).sendCode(anyString());

        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationBody()))
                .andExpect(status().isCreated());
    }

    // ---------------------------------------------------------------- account

    @Test
    void returnsTheAccountWithTheNameOfItsPerson() throws Exception {
        given(findUser.findByIdentifier("USR0000001")).willReturn(Optional.of(newAccount()));
        given(userProfileQuery.findByIds(List.of("USR0000001"))).willReturn(java.util.Map.of(
                "USR0000001", new UserProfile("USR0000001", "Ada", "Lovelace", EMAIL)));

        mvc.perform(get("/api/v1/auth/account").header("Authorization", bearerFor(identity())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.idUser").value("USR0000001"))
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.name").value("Ada"))
                .andExpect(jsonPath("$.lastName").value("Lovelace"));
    }

    @Test
    void deletesTheCallersOwnAccountAndAnswers204() throws Exception {
        mvc.perform(post("/api/v1/auth/account/delete")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"StrongPass1!\"}"))
                .andExpect(status().isNoContent());

        ArgumentCaptor<DeleteAccountCommand> command = ArgumentCaptor.forClass(DeleteAccountCommand.class);
        verify(deleteAccount).delete(command.capture());
        org.junit.jupiter.api.Assertions.assertEquals("USR0000001", command.getValue().idUser());
        org.junit.jupiter.api.Assertions.assertEquals("StrongPass1!", command.getValue().password());
    }

    @Test
    void answers401WhenTheDeletionPasswordIsWrong() throws Exception {
        willThrow(new CurrentPasswordMismatchException("current password does not match"))
                .given(deleteAccount).delete(any());

        mvc.perform(post("/api/v1/auth/account/delete")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refusesAnAccountDeletionWithoutAToken() throws Exception {
        mvc.perform(post("/api/v1/auth/account/delete")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"StrongPass1!\"}"))
                .andExpect(status().isUnauthorized());

        verifyNoInteractions(deleteAccount);
    }

    // ---------------------------------------------------------------- email verification
    // Each test uses its own caller address: the per-caller limiter is shared by the context.

    @Test
    void verifiesTheEmailWithTheCode() throws Exception {
        mvc.perform(post("/api/v1/auth/email/verify")
                        .with(request -> { request.setRemoteAddr("10.0.1.1"); return request; })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"someone@example.com\",\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Email verified."));

        verify(emailVerification).verify(EMAIL, "123456");
    }

    @Test
    void answers400ForAWrongCode() throws Exception {
        willThrow(new InvalidVerificationCodeException("The verification code is invalid or expired."))
                .given(emailVerification).verify(anyString(), anyString());

        mvc.perform(post("/api/v1/auth/email/verify")
                        .with(request -> { request.setRemoteAddr("10.0.1.2"); return request; })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"someone@example.com\",\"code\":\"654321\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("The verification code is invalid or expired."));
    }

    @Test
    void rejectsAVerificationCodeThatIsNotSixDigits() throws Exception {
        mvc.perform(post("/api/v1/auth/email/verify")
                        .with(request -> { request.setRemoteAddr("10.0.1.3"); return request; })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"someone@example.com\",\"code\":\"12ab\"}"))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(emailVerification);
    }

    @Test
    void answersAnEmptyAcceptedToAResendRequest() throws Exception {
        mvc.perform(post("/api/v1/auth/email/verification/resend")
                        .with(request -> { request.setRemoteAddr("10.0.1.4"); return request; })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"nobody@example.com\"}"))
                .andExpect(status().isAccepted())
                .andExpect(content().string(""));
    }

    @Test
    void passesTheSubmittedFieldsAndTheCallerAddressToTheUseCase() throws Exception {
        given(registerUser.register(any())).willReturn(newAccount());

        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationBody()))
                .andExpect(status().isCreated());

        verify(registerUser).register(any(RegisterUserCommand.class));
    }

    @Test
    void neverReturnsThePasswordHashOnRegistration() throws Exception {
        given(registerUser.register(any())).willReturn(newAccount());

        String body = mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationBody()))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        org.junit.jupiter.api.Assertions.assertFalse(body.contains("passwordHash"),
                "The response exposed the password hash");
        org.junit.jupiter.api.Assertions.assertFalse(body.contains("$2a$"),
                "The response exposed a BCrypt hash");
        org.junit.jupiter.api.Assertions.assertFalse(body.contains("StrongPass1!"),
                "The response echoed the plain password");
    }

    @Test
    void rejectsARegistrationWithABlankEmail() throws Exception {
        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"","password":"StrongPass1!","name":"Ada","lastName":"L"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.email").exists())
                .andExpect(jsonPath("$.path").value("/api/v1/auth/register"));

        verify(registerUser, never()).register(any());
    }

    @Test
    void rejectsARegistrationWithNoBody() throws Exception {
        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    @Test
    void answersConflictWhenTheEmailIsAlreadyRegistered() throws Exception {
        willThrow(new EmailAlreadyRegisteredException("Email already registered"))
                .given(registerUser).register(any());

        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationBody()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.message").value("Email already registered"));
    }

    @Test
    void answersUnprocessableWhenThePasswordBreaksThePolicy() throws Exception {
        willThrow(new PasswordPolicyViolationException("Password does not meet the policy"))
                .given(registerUser).register(any());

        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationBody()))
                .andExpect(status().isUnprocessableEntity());
    }

    // ----------------------------------------------------------------------- login

    @Test
    void signsInWithGoogleWithoutAnAccessToken() throws Exception {
        given(loginFlow.loginWithGoogle(any(), any(), any()))
                .willReturn(Optional.of(new SecurityLoginFlow.LoginOutcome("access-token",
                        "refresh-token", 900L, identity())));

        mvc.perform(post("/api/v1/auth/google")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"code":"4/0Ab-google-code"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access-token"))
                .andExpect(jsonPath("$.account.email").value(EMAIL));
    }

    @Test
    void anInvalidGoogleCodeIsUnauthorized() throws Exception {
        given(loginFlow.loginWithGoogle(any(), any(), any())).willReturn(Optional.empty());

        mvc.perform(post("/api/v1/auth/google")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"code":"expired"}
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void googleConflictsAndOutagesHaveTheirOwnStatus() throws Exception {
        given(loginFlow.loginWithGoogle(eq("taken"), any(), any())).willThrow(
                new com.energymonitor.security.application.exception.EmailAlreadyRegisteredException("taken"));
        given(loginFlow.loginWithGoogle(eq("off"), any(), any())).willThrow(
                new com.energymonitor.security.application.exception.GoogleSignInUnavailableException("off"));

        mvc.perform(post("/api/v1/auth/google").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"taken\"}"))
                .andExpect(status().isConflict());
        mvc.perform(post("/api/v1/auth/google").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"off\"}"))
                .andExpect(status().isServiceUnavailable());
        mvc.perform(post("/api/v1/auth/google").contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void logsInAndAnswersTheTokensAndTheAccount() throws Exception {
        given(loginFlow.login(any(), any(), any(), any()))
                .willReturn(Optional.of(new SecurityLoginFlow.LoginOutcome("access-token",
                        "refresh-token", 900L, identity())));

        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"someone@example.com","password":"StrongPass1!"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.account.idUser").value("USR0000001"))
                .andExpect(jsonPath("$.account.email").value(EMAIL));
    }

    @Test
    void neverExposesTheHashInsideTheLoginAccount() throws Exception {
        given(loginFlow.login(any(), any(), any(), any()))
                .willReturn(Optional.of(new SecurityLoginFlow.LoginOutcome("access-token",
                        "refresh-token", 900L, identity())));

        String body = mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"someone@example.com","password":"StrongPass1!"}
                                """))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        org.junit.jupiter.api.Assertions.assertFalse(body.contains("passwordHash"));
    }

    @Test
    void answersOneGenericUnauthorizedWhenTheAttemptIsRejected() throws Exception {
        given(loginFlow.login(any(), any(), any(), any())).willReturn(Optional.empty());

        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"someone@example.com","password":"wrong"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("Invalid credentials."));
    }

    @Test
    void rejectsALoginWithNoPassword() throws Exception {
        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"someone@example.com","password":""}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.password").exists());

        verify(loginFlow, never()).login(any(), any(), any(), any());
    }

    // ------------------------------------------------------------- password reset

    @Test
    void answersAnEmptyAcceptedForAKnownAccount() throws Exception {
        mvc.perform(post("/api/v1/auth/password/forgot")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"someone@example.com\"}"))
                .andExpect(status().isAccepted())
                .andExpect(content().string(""));
    }

    @Test
    void answersIdenticallyForAnUnknownAccountSoAddressesCannotBeEnumerated() throws Exception {
        willThrow(new UserNotFoundException("User not found"))
                .given(createPasswordResetToken).create(any());

        mvc.perform(post("/api/v1/auth/password/forgot")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"nobody@example.com\"}"))
                .andExpect(status().isAccepted())
                .andExpect(content().string(""));
    }

    @Test
    void neverReturnsTheResetTokenItJustMinted() throws Exception {
        // The token leaves through the delivery channel, which is a use case concern; the
        // response carries nothing at all, so there is nothing here to leak even by accident.
        Instant now = Instant.now();
        given(createPasswordResetToken.create(any()))
                .willReturn(com.energymonitor.security.domain.model.PasswordResetToken.issue(
                        "rst0000001", "USR0000001", "the-secret-reset-token-value",
                        "0".repeat(64), now, now.plusSeconds(900)));

        String body = mvc.perform(post("/api/v1/auth/password/forgot")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"someone@example.com\"}"))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();

        org.junit.jupiter.api.Assertions.assertTrue(body.isEmpty(),
                "The reset endpoint answered with a body instead of nothing");
        org.junit.jupiter.api.Assertions.assertFalse(body.contains("rst0000001"),
                "The reset endpoint leaked the reset token");
        org.junit.jupiter.api.Assertions.assertFalse(
                body.contains("the-secret-reset-token-value"),
                "The reset endpoint leaked the reset token value");
    }

    @Test
    void rejectsAnUnknownResetTokenWithBadRequest() throws Exception {
        willThrow(new com.energymonitor.security.application.exception.InvalidResetTokenException(
                "Reset token is invalid or expired"))
                .given(resetPassword).reset(any());

        mvc.perform(post("/api/v1/auth/password/reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"ada@example.com","resetToken":"000000","newPassword":"NewStrong1!"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Reset token is invalid or expired"));
    }

    @Test
    void completesAResetWithAValidToken() throws Exception {
        mvc.perform(post("/api/v1/auth/password/reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"ada@example.com","resetToken":"123456","newPassword":"NewStrong1!"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password updated."));
    }

    @Test
    void rejectsACodeThatIsNotSixDigitsBeforeReachingTheUseCase() throws Exception {
        // The shape is part of the design, not a formatting preference, so it is checked at the
        // edge: hashing a value of the wrong length could only fail at the lookup.
        mvc.perform(post("/api/v1/auth/password/reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"ada@example.com","resetToken":"12345","newPassword":"NewStrong1!"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.resetToken").exists());

        verifyNoInteractions(resetPassword);
    }

    @Test
    void ignoresAForwardedForHeaderAndRecordsTheRemoteAddress() throws Exception {
        // The header used to be the recorded address, which meant the caller chose it: the
        // password-recovery attempt limiter is keyed on this value, so a per-request header would
        // hand out a fresh allowance every time. The container's own remote address is the only
        // thing here that the client cannot set.
        mvc.perform(post("/api/v1/auth/password/reset")
                        .header("X-Forwarded-For", "203.0.113.99")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"ada@example.com","resetToken":"123456","newPassword":"NewStrong1!"}
                                """))
                .andExpect(status().isOk());

        ArgumentCaptor<ResetPasswordCommand> command =
                ArgumentCaptor.forClass(ResetPasswordCommand.class);
        verify(resetPassword).reset(command.capture());

        String recorded = command.getValue().ipAddress();
        assertNotNull(recorded, "the remote address should still be recorded");
        assertNotEquals("203.0.113.99", recorded, "the spoofed header was recorded as the caller");
    }

    // --------------------------------------------------------- protected endpoints

    @Test
    void changesThePasswordOfTheAuthenticatedCaller() throws Exception {
        mvc.perform(post("/api/v1/auth/password/change")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"currentPassword":"StrongPass1!","newPassword":"NewStrong1!"}
                                """))
                .andExpect(status().isOk());

        verify(changePassword).change(any());
    }

    @Test
    void readsTheAccountFromTheTokenAndNotFromTheRequest() throws Exception {
        mvc.perform(post("/api/v1/auth/password/change")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"currentPassword":"StrongPass1!","newPassword":"NewStrong1!"}
                                """))
                .andExpect(status().isOk());

        verify(changePassword).change(
                org.mockito.ArgumentMatchers.argThat(command ->
                        "USR0000001".equals(command.idUser())));
    }

    @Test
    void revokesTheSessionOfTheAuthenticatedCaller() throws Exception {
        mvc.perform(post("/api/v1/auth/logout")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"idUserSession\":\"SES0000001\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Session closed."));

        verify(logoutUserSession).logout(
                org.mockito.ArgumentMatchers.argThat(command ->
                        "SES0000001".equals(command.idUserSession())
                                && "USR0000001".equals(command.idUser())));
    }

    @Test
    void refusesToChangeThePasswordWithoutAToken() throws Exception {
        mvc.perform(post("/api/v1/auth/password/change")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"currentPassword":"StrongPass1!","newPassword":"NewStrong1!"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("A valid access token is required."));

        verify(changePassword, never()).change(any());
    }

    @Test
    void refusesToLogOutWithoutAToken() throws Exception {
        mvc.perform(post("/api/v1/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"idUserSession\":\"SES0000001\"}"))
                .andExpect(status().isUnauthorized());

        verify(logoutUserSession, never()).logout(any());
    }

    @Test
    void refusesATokenSignedWithAnotherKey() throws Exception {
        String forged = "eyJhbGciOiJIUzI1NiJ9"
                + ".eyJzdWIiOiJVU1IwMDAwMDAxIn0"
                + ".ZmFrZS1zaWduYXR1cmUtdGhhdC13aWxsLW5vdC12ZXJpZnk";

        mvc.perform(post("/api/v1/auth/logout")
                        .header("Authorization", "Bearer " + forged)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"idUserSession\":\"SES0000001\"}"))
                .andExpect(status().isUnauthorized());

        verify(logoutUserSession, never()).logout(any());
    }

    @Test
    void refusesAMalformedToken() throws Exception {
        mvc.perform(post("/api/v1/auth/logout")
                        .header("Authorization", "Bearer not-a-jwt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"idUserSession\":\"SES0000001\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void leavesRegistrationReachableWithoutAToken() throws Exception {
        // The permit list is what makes sign-up possible at all: a caller has no identity yet.
        given(registerUser.register(any())).willReturn(newAccount());

        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationBody()))
                .andExpect(status().isCreated());
    }

    @Test
    void reachesTheLoginUseCaseWithoutATokenRatherThanBeingBlockedByTheFilterChain() throws Exception {
        given(loginFlow.login(any(), any(), any(), any())).willReturn(Optional.empty());

        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"someone@example.com","password":"whatever"}
                                """))
                .andExpect(jsonPath("$.message").value("Invalid credentials."));

        verify(loginFlow).login(any(), any(), any(), any());
    }

    @Test
    void protectsEveryOtherRouteByDefault() throws Exception {
        mvc.perform(post("/api/v1/auth/password/forgot")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"nobody@example.com\"}"))
                .andExpect(status().isAccepted());

        mvc.perform(post("/api/v1/auth/unknown")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isUnauthorized());
    }

    // --------------------------------------------------------------- permissions

    @Test
    void listsThePermissionCodesOfTheAuthenticatedCaller() throws Exception {
        given(checkPermission.listGrantedCodes(anyString()))
                .willReturn(List.of("ALERT.READ", "METER.READ"));

        mvc.perform(get("/api/v1/auth/permissions")
                        .header("Authorization", bearerFor(identity())))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.permissions.length()").value(2))
                .andExpect(jsonPath("$.permissions[0]").value("ALERT.READ"))
                .andExpect(jsonPath("$.permissions[1]").value("METER.READ"));
    }

    @Test
    void readsThePermissionsOfTheTokenSubjectAndNotFromTheRequest() throws Exception {
        // The endpoint takes no parameter at all, so there is nothing for a caller to point
        // somewhere else: the subject of the validated token is the only input.
        given(checkPermission.listGrantedCodes(anyString())).willReturn(List.of());

        mvc.perform(get("/api/v1/auth/permissions")
                        .header("Authorization", bearerFor(identity()))
                        .param("idUser", "USR9999999"))
                .andExpect(status().isOk());

        verify(checkPermission).listGrantedCodes("USR0000001");
    }

    @Test
    void answersAnEmptyListWhenTheCallerHoldsNoPermission() throws Exception {
        // An authenticated account entitled to nothing is not an error: the client stays on one
        // code path instead of having to treat 200-with-nothing and 403 as two different cases.
        given(checkPermission.listGrantedCodes(anyString())).willReturn(List.of());

        mvc.perform(get("/api/v1/auth/permissions")
                        .header("Authorization", bearerFor(identity())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permissions").isEmpty());
    }

    @Test
    void answersNotFoundWhenTheTokenNamesAnAccountThatNoLongerExists() throws Exception {
        willThrow(new UserNotFoundException("no active user USR0000001"))
                .given(checkPermission).listGrantedCodes(anyString());

        mvc.perform(get("/api/v1/auth/permissions")
                        .header("Authorization", bearerFor(identity())))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.path").value("/api/v1/auth/permissions"));
    }

    @Test
    void refusesToListPermissionsWithoutAToken() throws Exception {
        mvc.perform(get("/api/v1/auth/permissions"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("A valid access token is required."));

        verify(checkPermission, never()).listGrantedCodes(anyString());
    }

    @Test
    void refusesToListPermissionsWithAMalformedToken() throws Exception {
        mvc.perform(get("/api/v1/auth/permissions")
                        .header("Authorization", "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized());

        verify(checkPermission, never()).listGrantedCodes(anyString());
    }

    @Test
    void refusesToListPermissionsWithATokenSignedWithAnotherKey() throws Exception {
        String forged = "eyJhbGciOiJIUzI1NiJ9"
                + ".eyJzdWIiOiJVU1IwMDAwMDAxIn0"
                + ".ZmFrZS1zaWduYXR1cmUtdGhhdC13aWxsLW5vdC12ZXJpZnk";

        mvc.perform(get("/api/v1/auth/permissions")
                        .header("Authorization", "Bearer " + forged))
                .andExpect(status().isUnauthorized());

        verify(checkPermission, never()).listGrantedCodes(anyString());
    }

    // -------------------------------------------------------------------- profile

    private static String profileBody() {
        return """
                {"name":"Grace","lastName":"Hopper","profileImage":"https://cdn.example.com/g.png",
                 "newEmail":"grace@example.com"}
                """;
    }

    /** The use case reports the profile it persisted, which is what the response must publish. */
    private void givenProfileSavedAs(String name, String lastName) {
        given(updateUserProfile.update(any()))
                .willReturn(new Person("PER0000001", name, lastName));
    }

    @Test
    void updatesTheProfileOfTheAuthenticatedCaller() throws Exception {
        givenProfileSavedAs("Grace", "Hopper");

        mvc.perform(put("/api/v1/auth/profile")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(profileBody()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.idPerson").value("PER0000001"))
                .andExpect(jsonPath("$.name").value("Grace"))
                .andExpect(jsonPath("$.lastName").value("Hopper"));
    }

    @Test
    void reportsTheProfileAsStoredRatherThanTheBodyThatWasSent() throws Exception {
        // The 200 body exists to separate a rename that was written from one that was merely
        // accepted, so it has to be built from what came back out of the use case.
        givenProfileSavedAs("Grace", "Hopper");

        mvc.perform(put("/api/v1/auth/profile")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name":"Hopper","lastName":"Grace"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Grace"))
                .andExpect(jsonPath("$.lastName").value("Hopper"));
    }

    @Test
    void handsTheNameToTheUseCaseSoTheRenameIsActuallyWritten() throws Exception {
        // The delivery layer's whole job here: a rename that never reaches the use case would
        // still answer 200, so the values crossing the boundary are asserted rather than the code.
        givenProfileSavedAs("Grace", "Hopper");

        mvc.perform(put("/api/v1/auth/profile")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(profileBody()))
                .andExpect(status().isOk());

        verify(updateUserProfile).update(
                org.mockito.ArgumentMatchers.argThat(command ->
                        "Grace".equals(command.name())
                                && "Hopper".equals(command.lastName())));
    }

    @Test
    void readsTheAccountToEditFromTheTokenAndNotFromTheBody() throws Exception {
        // There is no identity parameter on this endpoint at all. A body that names another
        // account is ignored as an unknown property, so the subject of the token stays the only
        // input and a caller cannot aim the edit at somebody else.
        givenProfileSavedAs("Grace", "Hopper");

        mvc.perform(put("/api/v1/auth/profile")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"idUser":"USR9999999","name":"Grace","lastName":"Hopper"}
                                """))
                .andExpect(status().isOk());

        verify(updateUserProfile).update(
                org.mockito.ArgumentMatchers.argThat(command ->
                        "USR0000001".equals(command.idUser())));
    }

    @Test
    void leavesAnAbsentFieldUnchangedRatherThanClearingIt() throws Exception {
        // An avatar-only request must not blank the name: absent arrives as null, which the use
        // case reads as "keep what is stored".
        givenProfileSavedAs("Ada", "Lovelace");

        mvc.perform(put("/api/v1/auth/profile")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"profileImage":"https://cdn.example.com/g.png"}
                                """))
                .andExpect(status().isOk());

        verify(updateUserProfile).update(
                org.mockito.ArgumentMatchers.argThat(command ->
                        command.name() == null
                                && command.lastName() == null
                                && command.newEmail() == null
                                && "https://cdn.example.com/g.png".equals(command.profileImage())));
    }

    @Test
    void ignoresAPhoneNumberAnOlderClientStillSends() throws Exception {
        // The field was removed from the model, the table and the contract. Accepting the body
        // rather than rejecting it keeps those clients working, and nothing from it is stored:
        // the response carries no contact number and the command has nowhere to put one.
        givenProfileSavedAs("Grace", "Hopper");

        String body = mvc.perform(put("/api/v1/auth/profile")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name":"Grace","lastName":"Hopper","phone":"+573001234567",
                                 "cellphone":"3001234567"}
                                """))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        org.junit.jupiter.api.Assertions.assertFalse(body.toLowerCase().contains("phone"),
                "The profile response still carries a phone number: " + body);
        org.junit.jupiter.api.Assertions.assertFalse(body.contains("+573001234567"),
                "The profile response echoed a phone number: " + body);
        verify(updateUserProfile).update(any());
    }

    @Test
    void refusesToUpdateTheProfileWithoutAToken() throws Exception {
        mvc.perform(put("/api/v1/auth/profile")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(profileBody()))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("A valid access token is required."));

        verify(updateUserProfile, never()).update(any());
    }

    @Test
    void refusesToUpdateTheProfileWithAMalformedToken() throws Exception {
        mvc.perform(put("/api/v1/auth/profile")
                        .header("Authorization", "Bearer not-a-jwt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(profileBody()))
                .andExpect(status().isUnauthorized());

        verify(updateUserProfile, never()).update(any());
    }

    @Test
    void refusesToUpdateTheProfileWithATokenSignedWithAnotherKey() throws Exception {
        String forged = "eyJhbGciOiJIUzI1NiJ9"
                + ".eyJzdWIiOiJVU1IwMDAwMDAxIn0"
                + ".ZmFrZS1zaWduYXR1cmUtdGhhdC13aWxsLW5vdC12ZXJpZnk";

        mvc.perform(put("/api/v1/auth/profile")
                        .header("Authorization", "Bearer " + forged)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(profileBody()))
                .andExpect(status().isUnauthorized());

        verify(updateUserProfile, never()).update(any());
    }

    @Test
    void answersNotFoundWhenTheAccountBehindTheTokenIsGone() throws Exception {
        willThrow(new UserNotFoundException("no active user USR0000001"))
                .given(updateUserProfile).update(any());

        mvc.perform(put("/api/v1/auth/profile")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(profileBody()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.path").value("/api/v1/auth/profile"));
    }

    @Test
    void answersConflictWhenTheNewAddressAlreadyBelongsToAnotherAccount() throws Exception {
        willThrow(new EmailAlreadyRegisteredException(
                "an account already exists for grace@example.com"))
                .given(updateUserProfile).update(any());

        mvc.perform(put("/api/v1/auth/profile")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(profileBody()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409));
    }

    @Test
    void rejectsANameTooLongForItsColumn() throws Exception {
        String tooLong = "a".repeat(101);

        mvc.perform(put("/api/v1/auth/profile")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name":"%s","lastName":"Hopper"}
                                """.formatted(tooLong)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.name").exists());

        verify(updateUserProfile, never()).update(any());
    }

    @Test
    void rejectsAMalformedNewAddress() throws Exception {
        mvc.perform(put("/api/v1/auth/profile")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"newEmail":"not-an-address"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.newEmail").exists());

        verify(updateUserProfile, never()).update(any());
    }

    @Test
    void rejectsAProfileUpdateWithNoBody() throws Exception {
        mvc.perform(put("/api/v1/auth/profile")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());

        verify(updateUserProfile, never()).update(any());
    }

    @Test
    void refusesTheProfileEditOnAVerbOtherThanPut() throws Exception {
        // The resource is replaced, not appended to: a POST would leave the previous name
        // undefined, so the mapping answers 405 instead of quietly accepting the body.
        givenProfileSavedAs("Grace", "Hopper");

        mvc.perform(post("/api/v1/auth/profile")
                        .header("Authorization", bearerFor(identity()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(profileBody()))
                .andExpect(status().isMethodNotAllowed());

        verify(updateUserProfile, never()).update(any());
    }

    @Test
    void publishesTheProfileEditAsAnAuthenticatedRouteInTheApiDescription() throws Exception {
        // A missing @SecurityRequirement does not break the filter chain, so nothing else would
        // notice: the endpoint would stay protected and the published document would quietly call
        // it public. The description is part of the contract, so it is asserted like one.
        JsonNode security = profileRoute().path("security");

        org.junit.jupiter.api.Assertions.assertFalse(security.isMissingNode(),
                "The published description shows the profile edit as reachable without a token");
        org.junit.jupiter.api.Assertions.assertTrue(
                security.path(0).has("bearerAuth"),
                "The profile edit is not published as a bearer-token route: " + security);
    }

    @Test
    void publishesExactlyTheResponseCodesTheProfileEditActuallyProduces() throws Exception {
        // A documented code that cannot occur is a promise the server does not keep, and the
        // handler is the only place that knows which ones do. 403 is the notable absence: the
        // use case asks for an account that is not deleted, not for one that can sign in.
        JsonNode responses = profileRoute().path("responses");
        List<String> documented = new java.util.ArrayList<>();
        responses.fieldNames().forEachRemaining(documented::add);

        org.junit.jupiter.api.Assertions.assertEquals(
                List.of("200", "400", "401", "404", "405", "409"),
                documented.stream().sorted().toList(),
                "The published codes for the profile edit do not match what it produces");
    }

    @Test
    void publishesAProfileBodyWithNoPhoneNumberInIt() throws Exception {
        // The removal is a contract fact and not only a schema one: a client reading the
        // published description must not find a contact number offered for editing.
        JsonNode properties = apiDescription()
                .at("/components/schemas/UpdateProfileRequest/properties");
        List<String> fields = new java.util.ArrayList<>();
        properties.fieldNames().forEachRemaining(fields::add);

        org.junit.jupiter.api.Assertions.assertEquals(
                List.of("name", "lastName", "profileImage", "newEmail"), fields,
                "The published profile body does not match the contract");
        org.junit.jupiter.api.Assertions.assertTrue(
                apiDescription().at("/components/schemas/UpdateProfileRequest/required")
                        .isMissingNode() || apiDescription()
                        .at("/components/schemas/UpdateProfileRequest/required").isEmpty(),
                "The published profile body claims a field is required, so an absent one is "
                        + "not an unchanged one");
    }

    /** The {@code put} operation of the profile route, as the description publishes it. */
    private JsonNode profileRoute() throws Exception {
        return apiDescription().at("/paths/~1api~1v1~1auth~1profile/put");
    }

    private JsonNode apiDescription() throws Exception {
        String document = mvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(document);
    }
}
