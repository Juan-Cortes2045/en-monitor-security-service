package com.energymonitor.security.adapter.in.web;

import com.energymonitor.security.infrastructure.SessionCookieProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

/**
 * Tokens in HttpOnly cookies, for the web app.
 *
 * <p>A client that sends {@value #TRANSPORT_HEADER}: {@value #TRANSPORT_COOKIE} at sign-in,
 * Google sign-in, refresh and sign-out receives and presents its tokens as cookies instead of in
 * the body, so no script on the page can read them and an XSS cannot steal the session. Without
 * the header (the mobile app) everything stays in the body, as before.
 *
 * <ul>
 *   <li>{@value #ACCESS_COOKIE}: the access token, {@code Path=/api}, as long as the token
 *       lives. The gateway turns it into the {@code Authorization} header it forwards, so the
 *       services behind it keep validating a bearer token.</li>
 *   <li>{@value #REFRESH_COOKIE}: the refresh token, {@code Path=/api/v1/auth}, so it only
 *       travels to the account endpoints and never to the rest of the API.</li>
 * </ul>
 *
 * <p>Both are {@code HttpOnly} and {@code SameSite=Strict}: a request started by another site
 * never carries them. On top of that, a refresh from the cookie needs the transport header, which
 * a cross-site form or image cannot send and a cross-origin script cannot either without the CORS
 * policy allowing it - the CSRF protection the ambient credential needs.
 */
@Component
@EnableConfigurationProperties(SessionCookieProperties.class)
public class SessionCookies {

    static final String TRANSPORT_HEADER = "X-Session-Transport";
    static final String TRANSPORT_COOKIE = "cookie";
    static final String ACCESS_COOKIE = "em_access";
    static final String REFRESH_COOKIE = "em_refresh";
    private static final String ACCESS_PATH = "/api";
    private static final String REFRESH_PATH = "/api/v1/auth";

    private final SessionCookieProperties properties;

    public SessionCookies(SessionCookieProperties properties) {
        this.properties = properties;
    }

    /** @return whether the caller asked for its tokens in cookies */
    public boolean requested(HttpServletRequest request) {
        return TRANSPORT_COOKIE.equalsIgnoreCase(request.getHeader(TRANSPORT_HEADER));
    }

    /** Sets both cookies, replacing the ones the browser holds. */
    public void write(HttpServletResponse response, String accessToken, long accessMaxAgeSeconds,
                      String refreshToken) {
        add(response, ACCESS_COOKIE, accessToken, ACCESS_PATH, Duration.ofSeconds(accessMaxAgeSeconds));
        add(response, REFRESH_COOKIE, refreshToken, REFRESH_PATH, properties.refreshMaxAge());
    }

    /** Tells the browser to drop both cookies. */
    public void clear(HttpServletResponse response) {
        add(response, ACCESS_COOKIE, "", ACCESS_PATH, Duration.ZERO);
        add(response, REFRESH_COOKIE, "", REFRESH_PATH, Duration.ZERO);
    }

    /** @return the refresh token the browser presented, if any */
    public Optional<String> refreshToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        return Arrays.stream(cookies)
                .filter(cookie -> REFRESH_COOKIE.equals(cookie.getName()))
                .map(Cookie::getValue)
                .filter(value -> !value.isBlank())
                .findFirst();
    }

    private void add(HttpServletResponse response, String name, String value, String path,
                     Duration maxAge) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(properties.secure())
                .sameSite("Strict")
                .path(path)
                .maxAge(maxAge)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
