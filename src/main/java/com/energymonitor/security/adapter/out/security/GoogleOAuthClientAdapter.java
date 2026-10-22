package com.energymonitor.security.adapter.out.security;

import com.energymonitor.security.application.port.out.GoogleIdentityPort;
import com.energymonitor.security.application.result.GoogleIdentity;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Google OAuth 2.0 client: exchanges the authorization code of the web app's popup
 * ({@code redirect_uri=postmessage}) for tokens, and verifies the returned ID token against
 * Google's keys, issuer and this client's id before trusting a single claim of it.
 *
 * <p>The code is single-use and only valid with the client secret, which never leaves the
 * server: a browser cannot make the backend believe it is somebody else.
 */
@Component
public class GoogleOAuthClientAdapter implements GoogleIdentityPort {

    private static final Logger LOG = LoggerFactory.getLogger(GoogleOAuthClientAdapter.class);
    private static final URI TOKEN_ENDPOINT = URI.create("https://oauth2.googleapis.com/token");
    private static final String JWKS = "https://www.googleapis.com/oauth2/v3/certs";
    private static final Set<String> ISSUERS = Set.of("accounts.google.com", "https://accounts.google.com");

    private final String clientId;
    private final String clientSecret;
    private final ObjectMapper objectMapper;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final NimbusJwtDecoder decoder;

    public GoogleOAuthClientAdapter(@Value("${security.google.client-id:}") String clientId,
                                    @Value("${security.google.client-secret:}") String clientSecret,
                                    ObjectMapper objectMapper) {
        this.clientId = clientId == null ? "" : clientId.trim();
        this.clientSecret = clientSecret == null ? "" : clientSecret.trim();
        this.objectMapper = objectMapper;
        this.decoder = NimbusJwtDecoder.withJwkSetUri(JWKS).build();
        this.decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                jwt -> ISSUERS.contains(String.valueOf(jwt.getClaims().get("iss")))
                        ? OAuth2TokenValidatorResult.success()
                        : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "issuer", null)),
                jwt -> jwt.getAudience() != null && jwt.getAudience().contains(this.clientId)
                        ? OAuth2TokenValidatorResult.success()
                        : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "audience", null))));
    }

    @Override
    public boolean isConfigured() {
        return !clientId.isEmpty() && !clientSecret.isEmpty();
    }

    @Override
    @SuppressWarnings("unchecked")
    public Optional<GoogleIdentity> exchange(String authorizationCode) {
        if (!isConfigured() || authorizationCode == null || authorizationCode.isBlank()) {
            return Optional.empty();
        }
        try {
            String form = Map.of(
                            "code", authorizationCode,
                            "client_id", clientId,
                            "client_secret", clientSecret,
                            "redirect_uri", "postmessage",
                            "grant_type", "authorization_code").entrySet().stream()
                    .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                    .collect(Collectors.joining("&"));
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(TOKEN_ENDPOINT)
                            .timeout(Duration.ofSeconds(15))
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .POST(HttpRequest.BodyPublishers.ofString(form))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                // The body says why (invalid_grant: expired or reused code), never a secret.
                LOG.info("Google rejected the authorization code: HTTP {} {}", response.statusCode(),
                        response.body());
                return Optional.empty();
            }
            Map<String, Object> tokens = objectMapper.readValue(response.body(), Map.class);
            Object idToken = tokens.get("id_token");
            if (!(idToken instanceof String raw)) {
                return Optional.empty();
            }
            Jwt jwt = decoder.decode(raw);
            return Optional.of(new GoogleIdentity(jwt.getSubject(), jwt.getClaimAsString("email"),
                    Boolean.TRUE.equals(jwt.getClaimAsBoolean("email_verified")),
                    jwt.getClaimAsString("given_name"), jwt.getClaimAsString("family_name"),
                    jwt.getClaimAsString("name"), jwt.getClaimAsString("picture")));
        } catch (JwtException e) {
            LOG.warn("Google ID token rejected: {}", e.getMessage());
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (Exception e) {
            LOG.warn("Google sign-in failed: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
