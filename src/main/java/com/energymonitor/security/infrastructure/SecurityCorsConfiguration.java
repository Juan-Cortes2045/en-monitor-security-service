package com.energymonitor.security.infrastructure;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Publishes the deployment's CORS policy as the {@code CorsConfigurationSource} Spring Security
 * looks for, so the {@code .cors(...)} call in {@link SecurityFilterChainConfiguration} stops
 * resolving to a same-origin-only default.
 *
 * <p><strong>Why the policy exists at all.</strong> CORS is a browser enforcement mechanism. The
 * React web frontend is served from a different origin than this API, so the browser refuses to
 * hand it a response unless this server says the calling origin is allowed. A native client such
 * as React Native does not apply CORS, so this configuration is what unblocks the web app and
 * nothing else.
 *
 * <h2>No wildcard origin</h2>
 *
 * <p>There is no {@code *} default here, and none can be configured, because a wildcard origin
 * means "any site on the internet may read this API's responses". For a bearer-token API that is
 * worse than useless: a page the user merely visits could issue authenticated requests and read
 * the answers. The origins are therefore whatever the deployment names in
 * {@code security.cors.allowed-origins}, which defaults to none.
 *
 * <h2>Credentials are off, and a wildcard with them cannot be configured</h2>
 *
 * <p>This API creates no cookie and no HTTP session, and the refresh token travels in the request
 * body, so {@code allowCredentials} is {@code false} and the policy never needs it. Two facts make
 * that the safe arrangement rather than merely the convenient one:
 *
 * <ul>
 *   <li>The Fetch specification forbids answering a credentialed request with a wildcard origin,
 *       and browsers reject such a response outright. A configuration combining {@code *} with
 *       credentials is therefore a deployment mistake that can only ever break the frontend in a
 *       way that is hard to diagnose, so it is refused at startup instead of at request time.</li>
 *   <li>The {@code Authorization} header a browser client sends is still readable by the
 *       application: it is a request header, not a cookie, so it does not depend on
 *       {@code allowCredentials} being true. Turning credentials on would add cookie support this
 *       API does not have while changing nothing about how the web client authenticates.</li>
 * </ul>
 *
 * <p>The trade-off of not allowing credentials is concrete: if the refresh token ever moves into
 * an {@code HttpOnly} cookie - the usual hardening for a browser client, since it takes the secret
 * out of reach of client-side code - then {@code allowCredentials} has to become {@code true}
 * here, the cookie needs {@code SameSite}, and CSRF protection has to be reconsidered for the
 * refresh endpoint for the reason recorded in {@link SecurityFilterChainConfiguration}. None of
 * that applies to the token-in-body design that is shipped.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SecurityCorsProperties.class)
public class SecurityCorsConfiguration {

    /** The one pattern the Fetch specification refuses to combine with credentials. */
    private static final String WILDCARD = "*";

    /**
     * Builds the source Spring Security resolves for every incoming request.
     *
     * <p>The policy is registered for {@code /**}, so a route added later is covered by the same
     * origin list rather than silently falling back to same-origin-only.
     *
     * @param properties the deployment's policy, already bound from configuration
     * @return the source consulted by the CORS filter
     * @throws IllegalStateException when the policy is one the Fetch specification cannot honour
     */
    @Bean
    public org.springframework.web.cors.CorsConfigurationSource corsConfigurationSource(
            SecurityCorsProperties properties) {
        List<String> origins = bareOrigins(properties.allowedOrigins());
        List<String> patterns = normalizedEntries(properties.allowedOriginPatterns());
        patterns = promotePatternsFromOrigins(patterns, properties.allowedOrigins());
        if (properties.allowCredentials()) {
            if (origins.contains(WILDCARD) || patterns.contains(WILDCARD)) {
                throw new IllegalStateException("Invalid CORS policy: security.cors allows the"
                        + " wildcard origin '*' together with allow-credentials=true. The Fetch"
                        + " specification forbids that combination and every browser rejects the"
                        + " response, so this configuration could only ever break the web client."
                        + " Name the origins explicitly, or turn allow-credentials off.");
            }
            if (origins.isEmpty() && patterns.isEmpty()) {
                throw new IllegalStateException("Invalid CORS policy: security.cors sets"
                        + " allow-credentials=true but lists no origin, so nothing could ever be"
                        + " answered with credentials.");
            }
        }

        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(origins);
        // Patterns are kept separate from origins because Spring only tolerates a wildcard in
        // this list, and it echoes the caller's concrete origin back rather than the pattern.
        configuration.setAllowedOriginPatterns(patterns);
        configuration.setAllowedMethods(properties.allowedMethods());
        configuration.setAllowedHeaders(properties.allowedHeaders());
        configuration.setExposedHeaders(properties.exposedHeaders());
        configuration.setAllowCredentials(properties.allowCredentials());
        configuration.setMaxAge(properties.maxAge());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Drops blanks and entries that are not {@code scheme://host[:port]}, so a mistyped origin
     * fails at startup instead of silently never matching a real request.
     *
     * <p>Validation is limited to the shape of the value rather than to a fixed scheme list,
     * because a staging environment is often reached over a scheme this code has no reason to
     * know about. What is enforced is that the value can never be a partial match, a path or a
     * pattern: {@code https://app.example.com/} and {@code https://app.example.com/api} would
     * both be accepted by the browser as different origins from {@code https://app.example.com},
     * so treating them as valid here would grant access to something the operator did not name.
     *
     * @param configured the configured values
     * @return the usable origins, in configuration order
     * @throws IllegalStateException when a value is not a bare origin
     */
    private static List<String> normalizedEntries(List<String> configured) {
        if (configured == null) {
            return List.of();
        }
        return configured.stream()
                .filter(origin -> origin != null && !origin.isBlank())
                .map(String::trim)
                .distinct()
                .toList();
    }

    private static boolean looksLikePattern(String value) {
        if (value == null) {
            return false;
        }
        return value.contains("*") || value.contains("?");
    }

    /**
     * The origins, each checked to be a bare {@code scheme://host[:port]}.
     *
     * @param configured the configured origins
     * @return the usable origins, in configuration order
     * @throws IllegalStateException when a value is not a bare origin
     */
    private static List<String> bareOrigins(List<String> configured) {
        return normalizedEntries(configured).stream()
                .filter(entry -> !looksLikePattern(entry))
                .peek(SecurityCorsConfiguration::requireBareOrigin)
                .toList();
    }

    private static List<String> promotePatternsFromOrigins(List<String> patterns,
                                                          List<String> originsConfigured) {
        List<String> promoted = new java.util.ArrayList<>(patterns);
        for (String entry : normalizedEntries(originsConfigured)) {
            if (looksLikePattern(entry) && !promoted.contains(entry)) {
                promoted.add(entry);
            }
        }
        return promoted;
    }

    private static void requireBareOrigin(String origin) {
        if (WILDCARD.equals(origin)) {
            return;
        }
        try {
            URI uri = new URI(origin);
            boolean shaped = uri.getScheme() != null && uri.getHost() != null
                    && uri.getUserInfo() == null && uri.getQuery() == null
                    && uri.getFragment() == null
                    && (uri.getPath() == null || uri.getPath().isEmpty());
            if (!shaped) {
                throw new IllegalStateException("Invalid CORS origin '" + origin + "': expected"
                        + " scheme://host[:port] with no path, query or fragment. The browser"
                        + " compares the whole origin, so a path would never match a request.");
            }
        } catch (URISyntaxException malformed) {
            throw new IllegalStateException("Invalid CORS origin '" + origin
                    + "': not a parsable origin.", malformed);
        }
    }
}
