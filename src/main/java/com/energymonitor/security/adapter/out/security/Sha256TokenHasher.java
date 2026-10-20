package com.energymonitor.security.adapter.out.security;

import com.energymonitor.security.application.port.out.PasswordResetTokenHasherPort;
import com.energymonitor.security.application.port.out.RefreshTokenHasherPort;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.springframework.stereotype.Component;

/**
 * SHA-256 implementation of {@link RefreshTokenHasherPort}.
 *
 * <p>This used to serve {@link PasswordResetTokenHasherPort} as well, and no longer does. The
 * reasoning below is correct for a 32-byte refresh token and wrong for a six-digit recovery code,
 * and that is the whole difference between them.
 *
 * <h2>Why SHA-256 and not BCrypt</h2>
 *
 * <p>The same codebase uses BCrypt for passwords, and reusing it here would look consistent
 * while being the wrong tool. BCrypt exists to make brute force expensive against a
 * <em>low-entropy</em> secret that a human chose and can be guessed from a dictionary. A refresh
 * token here is 32 bytes from {@link java.security.SecureRandom}: roughly 2^256 candidates, none
 * of which any list covers. There is nothing for a slow KDF to slow down, and a deliberate cost
 * factor would only add latency to every single refresh.
 *
 * <p>SHA-256 is therefore the appropriate primitive, and the cost it does add is irrelevant
 * because lookups are bounded by how often a client refreshes rather than by how often an
 * attacker guesses: an attacker cannot brute force a hash they have to fetch over the network.
 *
 * <p><strong>That last sentence is what stops applying to a recovery code.</strong> A code of six
 * digits has a million candidates, all of which fit in memory and all of which are cheap to
 * hash. Anyone holding a copy of the table recomputes the whole space in seconds, so a fast digest
 * there protects nothing. {@link PepperedHmacResetCodeHasher} serves that credential instead, and
 * keeps the deterministic output this class relies on for lookup.
 *
 * <h2>Representation</h2>
 *
 * <p>Lowercase hexadecimal, 64 characters for the 32-byte digest, matching
 * {@code refresh_token.token_hash VARCHAR(64)}.
 *
 * <p>Hex was chosen over Base64 for three reasons. It is the representation that survives the
 * most contexts unchanged, so a hash can be copied into a log, a support ticket or a manual
 * query without escaping. It is fixed width, so the column length is not a guess. And it is
 * emitted in a single case, which matters because the schema compares case-insensitively: a
 * Base64 hash could in principle collide with a differently-cased twin of itself, while a
 * lower-case hex string has only one spelling.
 */
@Component
public class Sha256TokenHasher implements RefreshTokenHasherPort {

    private static final String ALGORITHM = "SHA-256";
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /**
     * Digests the secret.
     *
     * <p>{@link MessageDigest} is stateful and not thread safe, so a fresh instance is created
     * per call rather than held in a field. The cost is negligible next to the digest itself.
     *
     * @param rawToken the secret in clear text
     * @return the lowercase hex SHA-256 of the UTF-8 bytes
     * @throws IllegalArgumentException if the secret is null or blank
     * @throws IllegalStateException    if the JVM does not provide SHA-256
     */
    @Override
    public String hash(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("rawToken must not be null or blank");
        }
        byte[] digest = digest(rawToken.getBytes(StandardCharsets.UTF_8));
        char[] hex = new char[digest.length * 2];
        for (int index = 0; index < digest.length; index++) {
            int value = digest[index] & 0xFF;
            hex[index * 2] = HEX[value >>> 4];
            hex[index * 2 + 1] = HEX[value & 0x0F];
        }
        return new String(hex);
    }

    private byte[] digest(byte[] input) {
        try {
            return MessageDigest.getInstance(ALGORITHM).digest(input);
        } catch (NoSuchAlgorithmException unavailable) {
            // SHA-256 is required of every Java platform, so this is not a runtime condition
            // any deployment can reach. Failing loudly beats silently storing something weaker.
            throw new IllegalStateException("SHA-256 is not available on this JVM", unavailable);
        }
    }
}
