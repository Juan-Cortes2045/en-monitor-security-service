package com.energymonitor.security.infrastructure;

import com.energymonitor.security.domain.model.PermissionCodes;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The HTTP security rules for the Security API.
 *
 * <p>The shape is a stateless bearer-token API:
 *
 * <ul>
 *   <li>No HTTP session is ever created, so nothing about a caller is kept server side and
 *       the API scales horizontally without sticky sessions.</li>
 *   <li>CSRF protection is off, which is correct precisely because there is no session and no
 *       cookie for a cross-site request to ride on. The refresh token is currently returned in
 *       the login response body and is meant to be sent back in a header, not attached
 *       automatically by the browser, so no ambient credential exists for a cross-site request
 *       to exploit. This reasoning is contingent: it stops being true if the refresh token
 *       moves into an ambient cookie, which is one of the reasons that decision is deferred to
 *       the refresh flow. At that point CSRF protection must be re-enabled for the refresh
 *       endpoint.</li>
 *   <li>Form login and HTTP Basic are off, so the only way in is a bearer token.</li>
 *   <li>JWT signature, issuer and expiry are validated by the resource server filter before a
 *       request reaches any controller.</li>
 * </ul>
 *
 * <p>Everything else is denied by default: a new endpoint is protected unless it is added to
 * the permit list on purpose.
 *
 * <h2>Administration</h2>
 *
 * <p>{@code /api/v1/admin/**} additionally requires a global permission code, resolved through
 * the RBAC chain by {@link PermissionAuthorization}: {@code USER.READ} to read the directory,
 * {@code USER.MANAGE} to change an account's state and {@code ROLE.MANAGE} to change its roles.
 * The administrator notifications live in energy-monitor-backend, which enforces its own rule.
 * Any other admin route is denied outright, so a new one stays closed until it is given a code
 * here. Home-scoped roles (owner, member) play no part in these rules.
 *
 * <h2>CORS</h2>
 *
 * <p>{@code cors(Customizer.withDefaults())} below resolves to the
 * {@code CorsConfigurationSource} bean published by {@link SecurityCorsConfiguration}. That bean
 * exists, so this is a real policy rather than the same-origin fallback Spring Security would
 * otherwise substitute: the server emits CORS headers for the origins the deployment names and
 * for no others.
 *
 * <p>It matters to the React web frontend, which is served from a different origin and would
 * otherwise be blocked by the browser. It does not affect React Native, because CORS is a browser
 * enforcement mechanism and a native HTTP client never applies it.
 *
 * <p>Which origins are allowed, whether credentials may ride along and why no wildcard exists
 * are argued in {@link SecurityCorsConfiguration}. The short version: the origins come from
 * configuration, they default to none, and credentials are off.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityFilterChainConfiguration {

    /**
     * Paths reachable without a token. Registration and login have no caller to authenticate,
     * completing a password reset is done with a reset token rather than a session, and refresh
     * is what a client calls precisely when its access token is no longer usable.
     *
     * <p><strong>What "reachable without a token" means.</strong> These paths are exempt from
     * requiring authentication; they are not exempt from authentication being validated. The
     * resource server filter still inspects an {@code Authorization: Bearer} header on any
     * request, including these, and refuses the request with 401 when that token is malformed,
     * expired or signed with another key. A client calling {@code /api/v1/auth/refresh} must
     * therefore send the refresh token on its own and omit the stale access token, which is the
     * shape the endpoint is designed for anyway.
     *
     * <p>The alternative, resolving the bearer token to empty for these paths so a stale header
     * would be ignored, is deliberately not implemented. It would mean treating an invalid
     * credential as acceptable on every public route, which is a much wider relaxation than
     * one endpoint needs, and there is no architectural requirement behind it: the refresh
     * secret is the authority for that call, and the client is told to present only it.
     */
    private static final String[] PUBLIC_ENDPOINTS = {
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/auth/google",
        "/api/v1/auth/refresh",
        "/api/v1/auth/password/forgot",
        "/api/v1/auth/password/reset",
        "/api/v1/auth/email/verify",
        "/api/v1/auth/email/verification/resend",
        // The public support page: read before signing in, often because signing in is the problem.
        "/api/v1/support/contacts"
    };

    /**
     * Unauthenticated access to the API description and the health probe, so a container
     * platform can still check liveness.
     */
    private static final String[] INFRASTRUCTURE_ENDPOINTS = {
        "/actuator/health",
        "/actuator/health/**",
        "/v3/api-docs/**",
        "/swagger-ui/**",
        "/swagger-ui.html"
    };

    /**
     * Builds the single filter chain protecting the API.
     *
     * @param http            the builder Spring Security hands over
     * @param entryPoint      renders 401 in the shared error shape
     * @param accessDenied    renders 403 in the shared error shape
     * @param permissions     enforces global permission codes on the admin routes
     * @return the installed filter chain
     * @throws Exception if the chain cannot be built
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                    JwtAuthenticationEntryPoint entryPoint,
                                                    JwtAccessDeniedHandler accessDenied,
                                                    PermissionAuthorization permissions)
            throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                // Resolves to the CorsConfigurationSource published by
                // SecurityCorsConfiguration: the origins named in configuration, no wildcard,
                // and no credentials. Without that bean this call would silently fall back to
                // same-origin-only and emit no CORS header at all.
                .cors(Customizer.withDefaults())
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDenied))
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .requestMatchers(INFRASTRUCTURE_ENDPOINTS).permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/admin/users", "/api/v1/admin/roles")
                        .access(permissions.require(PermissionCodes.USER_READ))
                        .requestMatchers(HttpMethod.PUT, "/api/v1/admin/users/*/status")
                        .access(permissions.require(PermissionCodes.USER_MANAGE))
                        .requestMatchers(HttpMethod.PUT, "/api/v1/admin/users/*/roles/*")
                        .access(permissions.require(PermissionCodes.ROLE_MANAGE))
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/admin/users/*/roles/*")
                        .access(permissions.require(PermissionCodes.ROLE_MANAGE))
                        .requestMatchers("/api/v1/admin/**").denyAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDenied)
                        .jwt(Customizer.withDefaults()))
                .build();
    }
}
