package com.energymonitor.security.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.containsStringIgnoringCase;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.energymonitor.security.application.port.in.CheckPermission;
import com.energymonitor.security.application.port.in.RegisterUser;
import com.energymonitor.security.application.port.in.RefreshSession;
import com.energymonitor.security.application.result.AuthenticatedUser;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.UserStatus;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * The CORS contract: which origins are answered, and what a preflight actually returns.
 *
 * <p>The origins are supplied to the context through the {@code properties} attribute above rather
 * than read from {@code application-local.yaml}, so the test states the policy it asserts about
 * instead of inheriting whatever the machine happens to have configured. The filter chain, the
 * published {@code CorsConfigurationSource} and the CORS filter itself are the real ones, so an
 * assertion that passes here means a browser would be satisfied the same way.
 */
@SpringBootTest(properties =
        "security.cors.allowed-origins=http://localhost:5173,https://app.example.com")
@AutoConfigureMockMvc
class SecurityCorsWebTest extends JwtKeyedTest {

    private static final String ALLOWED = "http://localhost:5173";
    private static final String OTHER_ALLOWED = "https://app.example.com";
    private static final String FOREIGN = "https://evil.example.org";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private JwtTokenIssuer tokenIssuer;

    @Autowired
    private CorsConfigurationSource corsConfigurationSource;

    @MockitoBean
    private RegisterUser registerUser;

    @MockitoBean
    private RefreshSession refreshSession;

    @MockitoBean
    private CheckPermission checkPermission;

    private CorsConfiguration policyFor(String path) {
        return corsConfigurationSource
                .getCorsConfiguration(new MockHttpServletRequest("OPTIONS", path));
    }

    // -------------------------------------------------------------------- preflight

    @Test
    void answersAPreflightFromAnAllowedOrigin() throws Exception {
        mvc.perform(options("/api/v1/auth/login")
                        .header("Origin", ALLOWED)
                        .header("Access-Control-Request-Method", "POST")
                        .header("Access-Control-Request-Headers", "content-type"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED));
    }

    @Test
    void publishesTheMethodThePreflightAskedAbout() throws Exception {
        // The browser decides whether to send the real request from these headers alone, so a
        // preflight that answered 200 without naming the method would be treated as a failure.
        mvc.perform(options("/api/v1/auth/login")
                        .header("Origin", ALLOWED)
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Methods", containsString("POST")));
    }

    @Test
    void publishesTheHeadersThePreflightAskedAbout() throws Exception {
        mvc.perform(options("/api/v1/auth/login")
                        .header("Origin", ALLOWED)
                        .header("Access-Control-Request-Method", "POST")
                        .header("Access-Control-Request-Headers", "authorization"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Headers",
                        containsStringIgnoringCase("Authorization")));
    }

    @Test
    void answersAHomesPreflightCarryingTheHeadersTheWebSends() throws Exception {
        mvc.perform(options("/api/v1/homes")
                        .header("Origin", ALLOWED)
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "authorization,content-type"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Headers",
                        containsStringIgnoringCase("Authorization")));
    }

    @Test
    void neverGrantsTheRetiredUserIdHeader() throws Exception {
        // The caller is the token's subject; a header naming a user is no longer read anywhere.
        // Spring answers a preflight with the subset of requested headers it allows, so asking
        // for authorization and x-user-id gets 200 with authorization alone. That omission is
        // what makes the browser refuse to send the real request.
        mvc.perform(options("/api/v1/homes")
                        .header("Origin", ALLOWED)
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "authorization,x-user-id"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Headers",
                        containsStringIgnoringCase("authorization")))
                .andExpect(header().string("Access-Control-Allow-Headers",
                        not(containsStringIgnoringCase("x-user-id"))));
    }

    @Test
    void refusesAPreflightThatOnlyAsksForTheRetiredUserIdHeader() throws Exception {
        // With nothing allowed among the requested headers, the preflight itself is refused.
        mvc.perform(options("/api/v1/homes")
                        .header("Origin", ALLOWED)
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "x-user-id"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Headers"));
    }

    @Test
    void letsTheBrowserCacheThePreflightAnswer() throws Exception {
        mvc.perform(options("/api/v1/auth/login")
                        .header("Origin", ALLOWED)
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Max-Age", "1800"));
    }

    @Test
    void answersAPreflightOnAProtectedRouteWithoutDemandingAToken() throws Exception {
        // A preflight carries no Authorization header by definition: the browser sends it before
        // it knows whether the real request will be allowed. Demanding a token here would make
        // every authenticated endpoint unreachable from a browser.
        mvc.perform(options("/api/v1/auth/account")
                        .header("Origin", ALLOWED)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED));
    }

    @Test
    void refusesAPreflightFromAnOriginThatIsNotAllowed() throws Exception {
        mvc.perform(options("/api/v1/auth/login")
                        .header("Origin", FOREIGN)
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    @Test
    void refusesAMethodThatIsNotInThePolicy() throws Exception {
        // OPTIONS is permitted, so a preflight asking for a verb the API does not offer must not
        // be answered with a wildcard that would let the browser go on to attempt it.
        mvc.perform(options("/api/v1/auth/login")
                        .header("Origin", ALLOWED)
                        .header("Access-Control-Request-Method", "PATCH"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Methods"));
    }

    @Test
    void answersTheDeletePreflightTheWebSendsToLeaveAHome() throws Exception {
        // The web client removes a member and leaves a home with DELETE. Refusing this preflight
        // makes both actions fail in the browser before the request ever reaches the API.
        mvc.perform(options("/api/v1/homes/x/members/me")
                        .header("Origin", ALLOWED)
                        .header("Access-Control-Request-Method", "DELETE")
                        .header("Access-Control-Request-Headers", "authorization"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED))
                .andExpect(header().string("Access-Control-Allow-Methods", containsString("DELETE")));
    }

    @Test
    void refusesTheDeletePreflightFromAnOriginThatIsNotAllowed() throws Exception {
        mvc.perform(options("/api/v1/homes/x/members/me")
                        .header("Origin", "http://evil.example")
                        .header("Access-Control-Request-Method", "DELETE")
                        .header("Access-Control-Request-Headers", "authorization"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    // --------------------------------------------------------------- actual requests

    @Test
    void stampsTheAllowOriginHeaderOnARealCrossOriginResponse() throws Exception {
        given(checkPermission.listGrantedCodes(any())).willReturn(List.of());
        var identity = new AuthenticatedUser("USR0000001", "PER0000001",
                Email.of("someone@example.com"), UserStatus.ACTIVE, Instant.now(), null);

        mvc.perform(get("/api/v1/auth/permissions")
                        .header("Origin", ALLOWED)
                        .header("Authorization", "Bearer " + tokenIssuer.issue(identity)))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED));
    }

    @Test
    void answersARejectedRequestWithTheCORSHeaderToo() throws Exception {
        // A 401 the browser cannot read is indistinguishable from a network failure, which is the
        // most confusing symptom a cross-origin client can be handed. The header has to be there.
        mvc.perform(get("/api/v1/auth/permissions").header("Origin", ALLOWED))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED));
    }

    @Test
    void refusesToStampAllowOriginForAnOriginThatIsNotAllowed() throws Exception {
        mvc.perform(post("/api/v1/auth/login")
                        .header("Origin", FOREIGN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"a@example.com\",\"password\":\"x\"}"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    @Test
    void echoesEveryConfiguredOriginRatherThanCollapsingThemIntoOne() throws Exception {
        // The browser compares the value it receives against the origin it sent, so answering
        // with a fixed string for two different origins would break one of them.
        mvc.perform(options("/api/v1/auth/login")
                        .header("Origin", ALLOWED)
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED));

        mvc.perform(options("/api/v1/auth/login")
                        .header("Origin", OTHER_ALLOWED)
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(header().string("Access-Control-Allow-Origin", OTHER_ALLOWED));
    }

    @Test
    void leavesASameOriginRequestWithoutCORSHeaders() throws Exception {
        // No Origin header means the browser is not enforcing CORS, so emitting the headers would
        // be noise. It also means non-browser clients are unaffected by this policy entirely.
        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    // ------------------------------------------------------------------ the policy

    @Test
    void publishesBothConfiguredOriginsAndNoOthers() {
        assertThat(policyFor("/api/v1/auth/login").getAllowedOrigins())
                .containsExactly(ALLOWED, OTHER_ALLOWED);
        assertThat(policyFor("/api/v1/auth/login").getAllowedOriginPatterns()).isEmpty();
    }

    @Test
    void appliesThePolicyToEveryRouteRatherThanOnlyThePublicOnes() {
        // One registered pattern is what stops a route added later from quietly falling back to
        // same-origin-only, which is the failure this configuration exists to prevent.
        assertThat(policyFor("/api/v1/anything/not/yet/written")).isNotNull();
    }

    @Test
    void keepsCredentialsOffSoNoCookieCouldEverRideAlong() {
        assertThat(policyFor("/api/v1/auth/login").getAllowCredentials()).isFalse();
    }

    @Test
    void neverPublishesAWildcardOrigin() {
        // A wildcard would let any site the user visits read authenticated responses.
        assertThat(policyFor("/api/v1/auth/login").getAllowedOrigins())
                .doesNotContain(CorsConfiguration.ALL);
        assertThat(policyFor("/api/v1/auth/login").getAllowedOriginPatterns())
                .doesNotContain(CorsConfiguration.ALL);
    }

    @Test
    void publishesTheMethodsAndHeadersTheApiActuallyUses() {
        CorsConfiguration policy = policyFor("/api/v1/auth/login");

        assertThat(policy.getAllowedMethods())
                .contains("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .doesNotContain("PATCH");
        assertThat(policy.getAllowedHeaders()).contains("Authorization", "Content-Type")
                .doesNotContain("X-User-Id");
    }

    @Test
    void exposesTheAllowHeaderSoA405IsReadableFromABrowser() {
        // The profile route answers 405 with the permitted verbs in Allow. A browser client cannot
        // read a header the server does not name here, so without this the detail stays server
        // side and the client sees a bare 405.
        assertThat(policyFor("/api/v1/auth/profile").getExposedHeaders()).contains("Allow");
    }
}
