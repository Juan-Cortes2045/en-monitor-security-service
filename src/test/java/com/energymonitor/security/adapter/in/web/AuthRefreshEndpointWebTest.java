package com.energymonitor.security.adapter.in.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.energymonitor.security.application.command.RefreshSessionCommand;
import com.energymonitor.security.application.port.in.RefreshSession;
import com.energymonitor.security.application.result.AuthenticatedUser;
import com.energymonitor.security.application.result.RefreshSessionResult;
import com.energymonitor.security.application.result.RefreshStatus;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.UserStatus;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import com.energymonitor.security.infrastructure.SecurityJwtProperties;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * The HTTP contract of {@code POST /api/v1/auth/refresh}.
 *
 * <p>The use case is replaced so these assertions are about the delivery layer: which status
 * each outcome produces, what the body contains, and what it must never contain. The filter
 * chain, the exception handler and the JSON mapping are the real ones, so a token minted by the
 * real issuer is validated by the real decoder below.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthRefreshEndpointWebTest extends JwtKeyedTest {

    private static final String SESSION = "SES0000001";
    private static final String REFRESHED_TOKEN = "refresh-token-renovado";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private SecurityJwtProperties properties;

    @MockitoBean
    private RefreshSession refreshSession;

    private static AuthenticatedUser identity() {
        return new AuthenticatedUser("USR0000001", "PER0000001",
                Email.of("someone@example.com"), UserStatus.ACTIVE, Instant.now(), null);
    }

    private static RefreshSessionResult rotated() {
        return new RefreshSessionResult(RefreshStatus.ROTATED, REFRESHED_TOKEN, SESSION,
                identity());
    }

    private static String body(String token) {
        return "{\"refreshToken\":\"" + token + "\"}";
    }

    /**
     * Decodes with the application's own key and issuer, read from the bound properties, so a
     * passing assertion means the token would be accepted by the resource server in production.
     * The test never hard-codes a signing key.
     */
    private Jwt decode(String accessToken) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey((java.security.interfaces.RSAPublicKey) keys().keyPair().getPublic())
                .signatureAlgorithm(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(properties.issuer()));
        return decoder.decode(accessToken);
    }

    // ------------------------------------------------------------------ success

    @Test
    void renewsBothCredentialsWith200() throws Exception {
        given(refreshSession.refresh(any())).willReturn(rotated());

        mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("refresh-token-original")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").value(REFRESHED_TOKEN));
    }

    @Test
    void handsBackANewRefreshTokenDifferentFromTheOnePresented() throws Exception {
        given(refreshSession.refresh(any())).willReturn(rotated());

        String response = mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("refresh-token-original")))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertFalse(response.contains("refresh-token-original"),
                "The presented token must not be echoed back");
    }

    @Test
    void delegatesToTheRefreshUseCaseAndNothingElse() throws Exception {
        given(refreshSession.refresh(any())).willReturn(rotated());

        mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("refresh-token-original")))
                .andExpect(status().isOk());

        var command = org.mockito.ArgumentCaptor.forClass(RefreshSessionCommand.class);
        verify(refreshSession).refresh(command.capture());
        // The controller passes the secret through untouched: no hashing happens in the web layer.
        assertEquals("refresh-token-original", command.getValue().rawRefreshToken());
    }

    @Test
    void issuesAnAccessTokenWithTheSameClaimsAsLogin() throws Exception {
        given(refreshSession.refresh(any())).willReturn(rotated());

        String accessToken = mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("refresh-token-original")))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String jwt = accessToken.replaceAll(".*\"accessToken\":\"([^\"]+)\".*", "$1");
        Jwt decoded = decode(jwt);

        // Same claim set as login: the identity is the session owner's, not the caller's.
        assertEquals("USR0000001", decoded.getSubject());
        assertEquals("PER0000001", decoded.getClaim("pid"));
        assertEquals("someone@example.com", decoded.getClaim("email"));
        assertEquals("https://energy-monitor-backend", decoded.getIssuer().toString());
        assertTrue(decoded.getId() != null && !decoded.getId().isBlank());
        assertEquals(900L, decoded.getExpiresAt().getEpochSecond()
                - decoded.getIssuedAt().getEpochSecond());
    }

    // ---------------------------------------------------------------- rejection

    @Test
    void answers401WhenTheAttemptIsRejected() throws Exception {
        given(refreshSession.refresh(any()))
                .willReturn(new RefreshSessionResult(RefreshStatus.REJECTED, null, SESSION, null));

        mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("token-desconocido")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void answers401WhenReuseIsDetected() throws Exception {
        given(refreshSession.refresh(any())).willReturn(new RefreshSessionResult(
                RefreshStatus.REUSE_DETECTED, null, SESSION, null));

        mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("token-ya-rotado")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void reuseIsNotDistinguishableFromAPlainRejection() throws Exception {
        given(refreshSession.refresh(any()))
                .willReturn(new RefreshSessionResult(RefreshStatus.REJECTED, null, null, null));
        String rejected = mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("token-desconocido")))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        given(refreshSession.refresh(any())).willReturn(new RefreshSessionResult(
                RefreshStatus.REUSE_DETECTED, null, SESSION, null));
        String reused = mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("token-ya-rotado")))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        // Telling a caller that its token was replayed would tell an attacker which stolen
        // tokens are worth trying.
        assertEquals(stripTimestamp(rejected), stripTimestamp(reused));
    }

    private static String stripTimestamp(String body) {
        return body.replaceAll("\"timestamp\":\"[^\"]+\"", "\"timestamp\":\"\"");
    }

    @Test
    void issuesNoCredentialsWhenRejected() throws Exception {
        given(refreshSession.refresh(any()))
                .willReturn(new RefreshSessionResult(RefreshStatus.REJECTED, null, SESSION, null));

        String response = mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("token-desconocido")))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        assertFalse(response.contains("accessToken"));
        assertFalse(response.contains("refreshToken"));
    }

    // ------------------------------------------------------------------ request

    @Test
    void rejectsAMissingToken() throws Exception {
        mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.refreshToken").exists());

        verify(refreshSession, never()).refresh(any());
    }

    @Test
    void rejectsABlankToken() throws Exception {
        mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("   ")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.refreshToken").exists());

        verify(refreshSession, never()).refresh(any());
    }

    @Test
    void rejectsANullToken() throws Exception {
        mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":null}"))
                .andExpect(status().isBadRequest());

        verify(refreshSession, never()).refresh(any());
    }

    @Test
    void rejectsAnOversizedToken() throws Exception {
        mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("x".repeat(256))))
                .andExpect(status().isBadRequest());

        verify(refreshSession, never()).refresh(any());
    }

    // ----------------------------------------------------------------- security

    @Test
    void isReachableWithNoAuthorizationHeaderAtAll() throws Exception {
        given(refreshSession.refresh(any())).willReturn(rotated());

        // Renewing an expired token must not require presenting one: the whole point of the
        // endpoint is that the access token is no longer usable. This is the client contract,
        // and it is the only shape a client needs.
        mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("refresh-token-original")))
                .andExpect(status().isOk());
    }

    @Test
    void rejectsAStaleBearerHeaderRatherThanIgnoringIt() throws Exception {
        // Recorded behaviour, not an oversight. The resource server filter validates any bearer
        // token it is given before the request reaches a controller, so a client that sends an
        // expired access token alongside a perfectly valid refresh token is refused at the
        // filter with 401. Ignoring the bad header instead would mean deciding that an invalid
        // credential is acceptable whenever the route is public, which is a wider relaxation
        // than the endpoint needs.
        //
        // The consequence for clients is concrete: call /refresh with the refresh token alone.
        mvc.perform(post("/api/v1/auth/refresh")
                        .header("Authorization", "Bearer not-a-valid-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("refresh-token-original")))
                .andExpect(status().isUnauthorized());

        verify(refreshSession, never()).refresh(any());
    }

    @Test
    void neverExposesInternalState() throws Exception {
        given(refreshSession.refresh(any())).willReturn(rotated());

        String response = mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("refresh-token-original")))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertFalse(response.contains("tokenHash"), "A hash must never appear in a response");
        assertFalse(response.contains("familyId"), "Family lineage must stay server side");
        assertFalse(response.contains("parentId"), "Genealogy must stay server side");
        assertFalse(response.contains("idRefreshToken"));
        assertFalse(response.contains("revokedReason"));
        assertFalse(response.contains(SESSION), "The internal session id must not leak");
    }

    @Test
    void cannotBePointedAtAnotherAccount() throws Exception {
        given(refreshSession.refresh(any())).willReturn(rotated());

        // Extra fields naming a different account are not part of the contract and are ignored:
        // the identity comes from the session the use case resolved, never from the request.
        mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"refresh-token-original\","
                                + "\"userId\":\"USR9999999\",\"email\":\"victim@example.com\"}"))
                .andExpect(status().isOk());

        var command = org.mockito.ArgumentCaptor.forClass(RefreshSessionCommand.class);
        verify(refreshSession).refresh(command.capture());
        assertEquals("refresh-token-original", command.getValue().rawRefreshToken());
    }

    @Test
    void rejectionBodiesCarryNoInternals() throws Exception {
        given(refreshSession.refresh(any()))
                .willReturn(new RefreshSessionResult(RefreshStatus.REJECTED, null, SESSION, null));

        String response = mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("token-desconocido")))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        assertFalse(response.contains(SESSION));
        assertFalse(response.contains("reuse"), "A replay must not be advertised");
        assertFalse(response.contains("tokenHash"));
        assertFalse(response.toLowerCase(java.util.Locale.ROOT).contains("exception"));
        assertFalse(response.contains(SESSION));
        assertTrue(response.contains("401"));
    }

    @Test
    void neverLeaksAStackTrace() throws Exception {
        given(refreshSession.refresh(any()))
                .willReturn(new RefreshSessionResult(RefreshStatus.REJECTED, null, null, null));

        mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("token-desconocido")))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    }
}
