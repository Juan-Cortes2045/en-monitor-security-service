package com.energymonitor.security.adapter.out.security;

import com.energymonitor.security.application.port.out.TokenGeneratorPort;
import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.stereotype.Component;

/**
 * Cryptographically secure implementation of {@link TokenGeneratorPort}.
 *
 * <p>The long token keeps 32 random bytes encoded as Base64URL, which gives 43 characters and
 * fits the roomier {@code user_session.refresh_token VARCHAR(255)}. Base64URL is used rather than
 * the standard alphabet because these values travel in URLs, cookies and headers, where
 * {@code +}, {@code /} and {@code =} would need escaping. The output carries 256 bits of
 * entropy from {@link SecureRandom}, so tokens are unguessable rather than merely unique.
 *
 * <p>The recovery code is the opposite trade and lives in the same adapter only because both come
 * from one source of randomness. It is six digits, chosen so a person can read it off a screen
 * and type it back; 20 bits is not a defence, and what defends it is the pepper on the stored
 * digest plus the rate limit on redemption. A code long enough to need no rate limit would be
 * exactly the thing nobody can type.
 *
 * <p>Its space is <strong>900,000</strong> rather than a million, because the leading digit is
 * drawn from 1 to 9 so the code never reads as a shorter number. Worth stating plainly rather
 * than rounding: it is about 19.8 bits, and it is the number the rate limit exists to bound.
 */
@Component
public class SecureTokenGeneratorAdapter implements TokenGeneratorPort {

    /**
     * Bytes of entropy per token. 32 bytes = 256 bits, encoded as 43 Base64URL characters.
     */
    private static final int TOKEN_BYTES = 32;

    /**
     * Ceiling for a digit that may follow the first one. Ten does not divide 256, so
     * {@code nextInt(10)} would map the residue of the random byte unevenly onto the digits and
     * make some of them a shade more likely than others.
     */
    private static final int UNBIASED_CEILING = 250;

    private final SecureRandom random = new SecureRandom();
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

    @Override
    public String generateToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return encoder.encodeToString(bytes);
    }

    @Override
    public String generateNumericCode(int digits) {
        if (digits < 1) {
            throw new IllegalArgumentException("digits must be at least 1, got " + digits);
        }
        StringBuilder code = new StringBuilder(digits);
        code.append(1 + random.nextInt(9));
        for (int position = 1; position < digits; position++) {
            code.append(unbiasedDigit());
        }
        return code.toString();
    }

    /**
     * Draws a digit with no modulo bias by rejecting the tail of the byte range.
     *
     * <p>{@code nextInt(10)} is already uniform in the JDK, but it is documented as
     * bias-prone in general and the fix is three lines, so this does it explicitly: bytes at or
     * above 250 are discarded and redrawn. The discarded fraction is 6 of 256, about 2.3%, which
     * costs one extra draw roughly once every forty digits.
     *
     * @return a digit from 0 to 9, each with the same probability
     */
    private int unbiasedDigit() {
        byte[] one = new byte[1];
        random.nextBytes(one);
        while ((one[0] & 0xFF) >= UNBIASED_CEILING) {
            random.nextBytes(one);
        }
        return (one[0] & 0xFF) % 10;
    }
}
