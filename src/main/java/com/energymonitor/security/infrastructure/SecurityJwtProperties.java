package com.energymonitor.security.infrastructure;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.jwt")
public record SecurityJwtProperties(
        String issuer,
        Duration accessTokenTtl,
        String privateKeyPath,
        String publicKeyPath) {
}
