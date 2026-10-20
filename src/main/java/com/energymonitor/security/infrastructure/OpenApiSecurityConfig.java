package com.energymonitor.security.infrastructure;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

/**
 * Declares the OpenAPI description and the one security scheme this API authenticates with.
 *
 * <p>The scheme is a stateless bearer token: the access token is a JWT signed with this
 * deployment's RSA key, so a client authenticates by sending
 * {@code Authorization: Bearer <token>} and nothing else. This is declared once, here, rather
 * than repeated per endpoint; the endpoints that require it say so with
 * {@code @SecurityRequirement(name = "bearerAuth")}, which is what keeps the public ones
 * (registration, sign-in, refresh, password reset) visibly public in the generated document
 * instead of inheriting a blanket requirement.
 *
 * <p>There is no {@code apiKey} cookie scheme because no credential is ambient: the API creates
 * no HTTP session and sets no cookie, and the refresh token travels in the response body.
 */
@Configuration
@OpenAPIDefinition(info = @Info(
        title = "Energy Monitor API",
        version = "v1",
        description = "Authentication, session and password management for Energy Monitor. "
                + "Stateless bearer-token API: no HTTP session and no cookie is created, so "
                + "every credential travels in the request or response body."))
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT")
public class OpenApiSecurityConfig {
}