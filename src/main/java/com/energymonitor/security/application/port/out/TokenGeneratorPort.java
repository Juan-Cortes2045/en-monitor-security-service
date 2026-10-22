package com.energymonitor.security.application.port.out;

/**
 * Output port for generating the random secrets the security aggregates store: session refresh
 * tokens and password-recovery codes. Nothing about their alphabet or length belongs to the
 * application layer.
 *
 * <p>Two shapes exist because the two credentials have different jobs. A refresh token is only
 * ever held by the machine that asked for it, so it is optimised for being unguessable and costs
 * nothing to be long. A recovery code has to survive being read off a screen by a person and
 * typed back, so it is optimised for being short, and is protected by a pepper and a rate limit
 * instead of by its own length.
 */
public interface TokenGeneratorPort {

    /**
     * Generates a fresh opaque token, 32 bytes of entropy rendered as 43 Base64URL characters.
     *
     * @return a non-blank random token value
     */
    String generateToken();

    /**
     * Generates a code of exactly {@code digits} decimal digits, uniformly distributed.
     *
     * <p>The leading digit is drawn from 1 to 9 rather than 0 to 9 so the code never reads as a
     * shorter number and never begins with a zero that a form might strip. Six digits therefore
     * yield 900,000 codes, not a million.
     *
     * @param digits how many digits the code has, at least 1
     * @return a numeric code of exactly {@code digits} characters
     * @throws IllegalArgumentException if {@code digits} is less than 1
     */
    String generateNumericCode(int digits);
}
