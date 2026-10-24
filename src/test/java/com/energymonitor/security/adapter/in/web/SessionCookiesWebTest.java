package com.energymonitor.security.adapter.in.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.energymonitor.security.application.exception.SessionNotFoundException;
import com.energymonitor.security.application.port.in.LogoutUserSession;
import com.energymonitor.security.application.port.in.RefreshSession;
import com.energymonitor.security.application.result.AuthenticatedUser;
import com.energymonitor.security.application.result.RefreshSessionResult;
import com.energymonitor.security.application.result.RefreshStatus;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.UserStatus;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import com.energymonitor.security.infrastructure.JwtTokenIssuer;
import com.energymonitor.security.infrastructure.SecurityLoginFlow;
import jakarta.servlet.http.Cookie;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Tokens in HttpOnly cookies ({@code X-Session-Transport: cookie}), the transport of the web app,
 * next to the body transport the mobile app keeps using.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SessionCookiesWebTest extends JwtKeyedTest {

    private static final String TRANSPORT = "X-Session-Transport";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private JwtTokenIssuer tokenIssuer;

    @MockitoBean
    private SecurityLoginFlow loginFlow;

    @MockitoBean
    private RefreshSession refreshSession;

    @MockitoBean
    private LogoutUserSession logoutUserSession;

    private static AuthenticatedUser identity() {
        return new AuthenticatedUser("USR0000001", "PER0000001", Email.of("ada@example.com"),
                UserStatus.ACTIVE, Instant.now(), null);
    }

    private static SecurityLoginFlow.LoginOutcome outcome() {
        return new SecurityLoginFlow.LoginOutcome("access-token", "refresh-token", 900L,
                identity(), "SES0000001");
    }

    private static List<String> setCookies(MvcResult result) {
        return result.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
    }

    private static String cookie(List<String> setCookies, String name) {
        return setCookies.stream().filter(c -> c.startsWith(name + "=")).findFirst().orElseThrow();
    }

    private String bearer() {
        return "Bearer " + tokenIssuer.issue(identity());
    }

    @Test
    void loginSetsHttpOnlyCookiesAndKeepsTheTokensOutOfTheBody() throws Exception {
        given(loginFlow.login(any(), any(), any(), any())).willReturn(Optional.of(outcome()));

        MvcResult result = mvc.perform(post("/api/v1/auth/login")
                        .header(TRANSPORT, "cookie")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"ada@example.com\",\"password\":\"StrongPass1!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andExpect(jsonPath("$.idUserSession").value("SES0000001"))
                .andExpect(jsonPath("$.account.idUser").value("USR0000001"))
                .andReturn();

        String access = cookie(setCookies(result), "em_access");
        String refresh = cookie(setCookies(result), "em_refresh");
        assertTrue(access.startsWith("em_access=access-token;"));
        assertTrue(access.contains("Path=/api;"));
        assertTrue(access.contains("Max-Age=900"));
        assertTrue(refresh.startsWith("em_refresh=refresh-token;"));
        assertTrue(refresh.contains("Path=/api/v1/auth;"));
        for (String c : List.of(access, refresh)) {
            assertTrue(c.contains("HttpOnly"), c);
            assertTrue(c.contains("SameSite=Strict"), c);
        }
    }

    @Test
    void loginWithoutTheHeaderKeepsTheTokensInTheBody() throws Exception {
        given(loginFlow.login(any(), any(), any(), any())).willReturn(Optional.of(outcome()));

        MvcResult result = mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"ada@example.com\",\"password\":\"StrongPass1!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                .andExpect(jsonPath("$.idUserSession").value("SES0000001"))
                .andReturn();

        assertTrue(setCookies(result).isEmpty());
    }

    @Test
    void refreshReadsTheCookieAndRotatesBoth() throws Exception {
        given(refreshSession.refresh(any())).willReturn(new RefreshSessionResult(
                RefreshStatus.ROTATED, "refresh-token-renovado", "SES0000001", identity()));

        MvcResult result = mvc.perform(post("/api/v1/auth/refresh")
                        .header(TRANSPORT, "cookie")
                        .cookie(new Cookie("em_refresh", "refresh-token")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andReturn();

        verify(refreshSession).refresh(argThat(command -> "refresh-token".equals(command.rawRefreshToken())));
        assertTrue(cookie(setCookies(result), "em_refresh").startsWith("em_refresh=refresh-token-renovado;"));
        assertTrue(cookie(setCookies(result), "em_access").contains("Max-Age=900"));
    }

    @Test
    void refreshWithoutTheCookieIsAnExpiredSession() throws Exception {
        mvc.perform(post("/api/v1/auth/refresh").header(TRANSPORT, "cookie"))
                .andExpect(status().isUnauthorized());

        verify(refreshSession, never()).refresh(any());
    }

    @Test
    void theRefreshCookieAloneIsNotEnough() throws Exception {
        // Without the transport header (which a cross-site form or image cannot send) the cookie
        // is not read: the request is just a refresh without a body.
        mvc.perform(post("/api/v1/auth/refresh").cookie(new Cookie("em_refresh", "refresh-token")))
                .andExpect(status().isBadRequest());

        verify(refreshSession, never()).refresh(any());
    }

    @Test
    void aRejectedCookieRefreshClearsTheCookies() throws Exception {
        given(refreshSession.refresh(any())).willReturn(new RefreshSessionResult(
                RefreshStatus.REJECTED, null, null, null));

        MvcResult result = mvc.perform(post("/api/v1/auth/refresh")
                        .header(TRANSPORT, "cookie")
                        .cookie(new Cookie("em_refresh", "token-desconocido")))
                .andExpect(status().isUnauthorized())
                .andReturn();

        assertTrue(cookie(setCookies(result), "em_access").contains("Max-Age=0"));
        assertTrue(cookie(setCookies(result), "em_refresh").contains("Max-Age=0"));
    }

    @Test
    void logoutClearsTheCookies() throws Exception {
        MvcResult result = mvc.perform(post("/api/v1/auth/logout")
                        .header(TRANSPORT, "cookie")
                        .header(HttpHeaders.AUTHORIZATION, bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"idUserSession\":\"SES0000001\"}"))
                .andExpect(status().isOk())
                .andReturn();

        assertEquals("em_access=", cookie(setCookies(result), "em_access").substring(0, 10));
        assertTrue(cookie(setCookies(result), "em_access").contains("Max-Age=0"));
        assertTrue(cookie(setCookies(result), "em_refresh").contains("Max-Age=0"));
    }

    @Test
    void logoutClearsTheCookiesEvenWhenTheSessionWasAlreadyGone() throws Exception {
        willThrow(new SessionNotFoundException("no active session SES0000001"))
                .given(logoutUserSession).logout(any());

        mvc.perform(post("/api/v1/auth/logout")
                        .header(TRANSPORT, "cookie")
                        .header(HttpHeaders.AUTHORIZATION, bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"idUserSession\":\"SES0000001\"}"))
                .andExpect(status().isNotFound())
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE,
                        org.hamcrest.Matchers.hasItem(org.hamcrest.Matchers.startsWith("em_refresh=;"))));
    }
}
