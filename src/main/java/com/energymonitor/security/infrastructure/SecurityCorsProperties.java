package com.energymonitor.security.infrastructure;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * The deployment's CORS policy, bound from configuration.
 *
 * <p><strong>Why this is configuration and not a constant.</strong> An allowed origin is a fact
 * about <em>where this deployment is called from</em>, and that changes per environment: the
 * React web app runs on {@code localhost:5173} in development and on some domain in production.
 * A hardcoded list would be wrong in at least one of them, and the failure mode is quiet - the
 * browser blocks the response and the developer reads it as an authentication bug. Binding the
 * list means each environment states its own origins and a typo fails at startup rather than in
 * a browser console.
 *
 * <p><strong>Why the defaults are empty rather than permissive.</strong> {@link #allowedOrigins()}
 * defaults to nothing, which means no cross-origin caller is answered at all. An API nobody has
 * yet integrated is better off refusing every origin than silently trusting every one of them:
 * the cost of the strict default is a configuration line when a real frontend appears, and the
 * cost of the permissive one is a security hole nobody chose.
 *
 * <p><strong>Origins are matched exactly, not by suffix.</strong> {@link #allowedOrigins()} takes
 * literal values such as {@code https://app.example.com}. Patterns such as
 * {@code https://*.example.com} belong in {@link #allowedOriginPatterns()}, which Spring
 * matches with a wildcard rule and which, unlike {@code allowedOrigins}, is still allowed to be
 * combined with credentials.
 *
 * <p><strong>Why the default methods include {@code DELETE} but not {@code PATCH}.</strong> The
 * list names the verbs the web client actually sends. It removes a member from a home and leaves
 * a home with {@code DELETE /api/v1/homes/{homeId}/members/...}; without {@code DELETE} here the
 * browser's preflight is refused with {@code 403} and both actions fail before reaching the API.
 * No route answers {@code PATCH}, so it stays out rather than being allowed speculatively.
 *
 * @param allowedOrigins         the exact origins permitted, empty to permit none
 * @param allowedOriginPatterns  origin patterns permitted, empty for none
 * @param allowedMethods         the HTTP methods a permitted origin may use
 * @param allowedHeaders         the request headers a permitted origin may send
 * @param exposedHeaders         the response headers the browser may read
 * @param allowCredentials       whether cookies and {@code Authorization} may ride along; see
 *                               {@link SecurityCorsConfiguration} for why this API does not
 *                               need it
 * @param maxAge                 how long a browser may cache the preflight answer
 */
@ConfigurationProperties(prefix = "security.cors")
public record SecurityCorsProperties(
        @DefaultValue List<String> allowedOrigins,
        @DefaultValue List<String> allowedOriginPatterns,
        @DefaultValue({"GET", "POST", "PUT", "DELETE", "OPTIONS"}) List<String> allowedMethods,
        @DefaultValue({"Authorization", "Content-Type", "Accept"}) List<String> allowedHeaders,
        @DefaultValue({"Allow", "Retry-After"}) List<String> exposedHeaders,
        @DefaultValue("false") boolean allowCredentials,
        @DefaultValue("30m") Duration maxAge) {
}
