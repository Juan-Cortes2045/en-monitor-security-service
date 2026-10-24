package com.energymonitor.security.infrastructure;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * The HttpOnly cookies the web app receives its tokens in ({@code SessionCookies}).
 *
 * @param secure        whether the cookies carry {@code Secure}. On by default, which is what a
 *                      deployment behind HTTPS needs; the local stack and development mode
 *                      serve plain HTTP and turn it off, otherwise the browser would drop them
 * @param refreshMaxAge how long the browser keeps the refresh cookie: the lifetime of the
 *                      refresh token itself, seven days
 */
@ConfigurationProperties(prefix = "security.session-cookie")
public record SessionCookieProperties(
        @DefaultValue("true") boolean secure,
        @DefaultValue("7d") Duration refreshMaxAge) {
}
