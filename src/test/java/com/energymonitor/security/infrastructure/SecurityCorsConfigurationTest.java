package com.energymonitor.security.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.web.cors.CorsConfiguration;

/**
 * The guards on the CORS policy, exercised without booting a context.
 *
 * <p>Each case here is a configuration an operator could plausibly type and a browser could
 * plausibly be harmed by. Failing at startup, with a message naming the property, is what turns
 * those from a mystery in a browser console into a startup error.
 */
class SecurityCorsConfigurationTest {

    private static SecurityCorsProperties properties(List<String> origins,
                                                     List<String> patterns,
                                                     boolean allowCredentials) {
        return new SecurityCorsProperties(origins, patterns, List.of("GET", "POST"),
                List.of("Authorization"), List.of("Allow"), allowCredentials,
                Duration.ofMinutes(30));
    }

    private static SecurityCorsConfiguration configuration() {
        return new SecurityCorsConfiguration();
    }

    // ------------------------------------------------------------------ wildcards

    @Test
    void refusesAWildcardOriginTogetherWithCredentials() {
        var wildcardWithCredentials = properties(List.of("*"), List.of(), true);

        assertThatThrownBy(() -> configuration().corsConfigurationSource(wildcardWithCredentials))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("security.cors")
                .hasMessageContaining("allow-credentials");
    }

    @Test
    void refusesAWildcardOriginPatternTogetherWithCredentials() {
        // Spring tolerates a wildcard in the pattern list, so this is the shape that would
        // otherwise slip past and produce a response every browser rejects.
        var patternWithCredentials = properties(List.of(), List.of("*"), true);

        assertThatThrownBy(() -> configuration().corsConfigurationSource(patternWithCredentials))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("allow-credentials");
    }

    @Test
    void allowsAWildcardOriginWhenCredentialsAreOff() {
        // Not forbidden by the Fetch specification, and refusing it would leave a non-browser
        // test client with no way to opt in. It is still not the default.
        var wildcardWithoutCredentials = properties(List.of("*"), List.of(), false);

        var source = configuration().corsConfigurationSource(wildcardWithoutCredentials);

        assertThat(source.getCorsConfiguration(
                new org.springframework.mock.web.MockHttpServletRequest("OPTIONS", "/api")))
                .isNotNull();
    }

    @Test
    void refusesCredentialsWithNoOriginAtAll() {
        var credentialsAndNoOrigin = properties(List.of(), List.of(), true);

        assertThatThrownBy(() -> configuration().corsConfigurationSource(credentialsAndNoOrigin))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no origin");
    }

    // ----------------------------------------------------------- origin validation

    @Test
    void refusesAnOriginCarryingAPath() {
        // The browser compares the whole origin, so a path-bearing value would silently never
        // match anything. Rejecting it at startup beats a frontend that cannot be diagnosed.
        var withPath = properties(List.of("https://app.example.com/api"), List.of(), false);

        assertThatThrownBy(() -> configuration().corsConfigurationSource(withPath))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("https://app.example.com/api");
    }

    @Test
    void refusesAnOriginWithATrailingSlash() {
        // A trailing slash is the most common way this goes wrong: it looks identical to the
        // working value and matches nothing.
        var withSlash = properties(List.of("https://app.example.com/"), List.of(), false);

        assertThatThrownBy(() -> configuration().corsConfigurationSource(withSlash))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void refusesAValueThatIsNotAnOrigin() {
        assertThatThrownBy(() -> configuration().corsConfigurationSource(
                properties(List.of("app.example.com"), List.of(), false)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("scheme://host");
    }

    @Test
    void refusesAnOriginCarryingUserInfo() {
        // "https://trusted.example.com@evil.example.org" is a real origin for evil.example.org.
        var withUserInfo = properties(List.of("https://trusted.example.com@evil.example.org"),
                List.of(), false);

        assertThatThrownBy(() -> configuration().corsConfigurationSource(withUserInfo))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void dropsBlankEntriesRatherThanPublishingAnEmptyOrigin() {
        var withBlanks = properties(List.of(" ", "", "https://app.example.com"), List.of(), false);

        var configuration = new SecurityCorsConfiguration()
                .corsConfigurationSource(withBlanks)
                .getCorsConfiguration(
                        new org.springframework.mock.web.MockHttpServletRequest("OPTIONS", "/x"));

        assertThat(configuration.getAllowedOrigins())
                .containsExactly("https://app.example.com");
    }

    // ---------------------------------------------------------------- empty policy

    @Test
    void publishesAnEmptyPolicyWhenNoOriginIsConfigured() {
        // The default state of a fresh deployment: a source exists and permits nothing, so no
        // cross-origin caller is answered. That is the fail-closed direction.
        var nothing = properties(List.of(), List.of(), false);

        var configuration = new SecurityCorsConfiguration()
                .corsConfigurationSource(nothing)
                .getCorsConfiguration(
                        new org.springframework.mock.web.MockHttpServletRequest("OPTIONS", "/x"));

        assertThat(configuration.getAllowedOrigins()).isEmpty();
        assertThat(configuration.getAllowedOriginPatterns()).isEmpty();
        assertThat(configuration.getAllowCredentials()).isFalse();
    }

    @Test
    void keepsPatternsOutOfTheOriginsList() {
        // Spring only tolerates a wildcard in the pattern list and echoes the concrete origin
        // back, so mixing the two would produce a response the browser rejects.
        var separate = properties(List.of("https://app.example.com"),
                List.of("https://*.example.org"), false);

        CorsConfiguration configuration = new SecurityCorsConfiguration()
                .corsConfigurationSource(separate)
                .getCorsConfiguration(
                        new org.springframework.mock.web.MockHttpServletRequest("OPTIONS", "/x"));

        assertThat(configuration.getAllowedOrigins()).containsExactly("https://app.example.com");
        assertThat(configuration.getAllowedOriginPatterns())
                .containsExactly("https://*.example.org");
    }
}
