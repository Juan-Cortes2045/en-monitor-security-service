package com.energymonitor.security.infrastructure;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Settings for password-recovery codes, bound from {@code security.reset.*}.
 *
 * <p>Grouped in one record because the four values only make sense together: the code length,
 * how long it lives, and how many guesses a caller may spend on it are one decision about how
 * hard a six-digit code is to guess. Splitting them across records would let a deployment end up
 * with a shorter code and a looser limit, which is the wrong way round.
 *
 * @param pepper              secret mixed into the stored digest, supplied per environment
 * @param codeDigits          how many digits a recovery code has
 * @param codeValidity        how long a freshly issued code stays redeemable
 * @param maxAttemptsPerWindow redemption attempts one caller address may make per window
 * @param attemptWindow       length of that window
 */
@ConfigurationProperties(prefix = "security.reset")
public record SecurityResetProperties(
        String pepper,
        Integer codeDigits,
        Duration codeValidity,
        Integer maxAttemptsPerWindow,
        Duration attemptWindow) {
}
