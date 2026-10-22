package com.energymonitor.security.adapter.out.security;

import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import java.security.SecureRandom;
import org.springframework.stereotype.Component;

/**
 * Cryptographically secure implementation of {@link IdentifierGeneratorPort}.
 *
 * <p>Every business identifier column is {@code VARCHAR(10)}, so the generator emits exactly
 * ten characters drawn from {@code [0-9a-z]}: 36^10 combinations, roughly 52 bits of
 * entropy, which makes a collision negligible for a user base of this size while the
 * primary keys remain the ultimate guarantee.
 *
 * <p>Lower case only is deliberate. The schema uses a case-insensitive collation, so mixing
 * upper and lower case letters would make distinct generated values collide on comparison
 * even though they differ as strings.
 */
@Component
public class SecureIdentifierGeneratorAdapter implements IdentifierGeneratorPort {

    /** Matches the {@code VARCHAR(10)} business identifier columns. */
    private static final int IDENTIFIER_LENGTH = 10;

    private static final char[] ALPHABET =
            "0123456789abcdefghijklmnopqrstuvwxyz".toCharArray();

    private final SecureRandom random = new SecureRandom();

    @Override
    public String generate() {
        StringBuilder identifier = new StringBuilder(IDENTIFIER_LENGTH);
        for (int position = 0; position < IDENTIFIER_LENGTH; position++) {
            identifier.append(ALPHABET[random.nextInt(ALPHABET.length)]);
        }
        return identifier.toString();
    }
}
