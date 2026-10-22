package com.energymonitor.security.adapter.out.security;

import com.energymonitor.security.application.port.out.PasswordResetTokenHasherPort;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA256 with a pepper, used for the password-recovery code.
 *
 * <p>This adapter replaced {@link Sha256TokenHasher} for this one credential, and the reason is
 * entirely about how much entropy the secret has. A refresh token is 32 bytes from
 * {@link java.security.SecureRandom}: roughly 2^256 candidates, so a fast digest is the right
 * primitive and a slow KDF would only add latency. A recovery code is six digits: about 2^20,
 * which is a few minutes of hashing on any machine. Against that, a fast digest is not a
 * protection at all, because whoever copies the table recomputes all one million codes and
 * recovers every outstanding code in the database.
 *
 * <h2>Why HMAC and not BCrypt</h2>
 *
 * <p>BCrypt is the obvious way to make a small secret expensive, and it is the wrong tool here
 * for a structural reason rather than a preference: it is salted and therefore non-deterministic,
 * so the same code hashes differently every time. The recovery flow resolves a code to its row
 * <em>by</em> hashing the presented value and looking that up
 * ({@code PasswordResetTokenRepository.findByResetTokenHash...}). With BCrypt there is no stable
 * value to look up, so redemption would have to scan the outstanding codes and verify each one.
 *
 * <p>HMAC keeps the digest deterministic, which is what makes comparing a presented code with a
 * stored one possible, and moves the attacker's problem: brute force now needs the pepper as well
 * as the table.
 *
 * <h2>Why the pepper is not simply a longer secret</h2>
 *
 * <p>Because a secret stored next to its own hash is not a secret from whoever steals the table.
 * The pepper is configuration, lives outside the database, and is supplied per environment. An
 * attacker with only a dump cannot compute a single candidate hash without it.
 *
 * <p>The output is lowercase hexadecimal, 64 characters, which still fits
 * {@code password_reset_token.reset_token_hash VARCHAR(64)} and keeps the existing unique index
 * usable as a lookup key.
 */
public class PepperedHmacResetCodeHasher implements PasswordResetTokenHasherPort {

    private static final String ALGORITHM = "HmacSHA256";

    /**
     * Separates the account from the code inside the hashed material, so that
     * {@code ("ab", "c")} and {@code ("a", "bc")} cannot produce the same digest.
     */
    private static final String SEPARATOR = ":";

    private static final int MIN_PEPPER_BYTES = 16;

    private final byte[] pepper;

    /**
     * @param pepper the configured pepper, at least 16 bytes so a short value cannot be found by
     *               trying the plausible ones
     * @throws IllegalArgumentException if the pepper is missing, blank or too short
     */
    public PepperedHmacResetCodeHasher(String pepper) {
        if (pepper == null || pepper.isBlank()) {
            throw new IllegalArgumentException(
                    "security.reset.pepper must be set: the password-recovery code is six digits, so"
                            + " an unpeppered digest of it can be reversed from a database dump."
                            + " Generate one with 'openssl rand -hex 32' and set SECURITY_RESET_PEPPER.");
        }
        this.pepper = pepper.trim().getBytes(StandardCharsets.UTF_8);
        if (this.pepper.length < MIN_PEPPER_BYTES) {
            throw new IllegalArgumentException(
                    "security.reset.pepper must be at least " + MIN_PEPPER_BYTES
                            + " bytes; got " + this.pepper.length);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Computes {@code HMAC-SHA256(idUser + ":" + code, pepper)}. The separator is part of the
     * construction and not decoration: without it, {@code ("ab", "c")} and {@code ("a", "bc")}
     * would hash the same string and two different pairs would collide.
     *
     * @param idUser    the account the code belongs to
     * @param clearCode the recovery code in clear text
     * @return the lowercase hex digest, 64 characters
     * @throws IllegalArgumentException if either argument is null or blank
     * @throws IllegalStateException    if the JVM lacks HMAC-SHA256, which every Java platform has
     */
    @Override
    public String hash(String idUser, String clearCode) {
        if (idUser == null || idUser.isBlank()) {
            throw new IllegalArgumentException("idUser must not be null or blank");
        }
        if (clearCode == null || clearCode.isBlank()) {
            throw new IllegalArgumentException("clearCode must not be null or blank");
        }
        Mac mac = mac();
        return HexFormat.of().formatHex(
                mac.doFinal((idUser + SEPARATOR + clearCode).getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * {@link Mac} is stateful and not thread safe, so a fresh instance is created per call. It
     * also cannot be cloned usefully across threads for the same reason.
     */
    private Mac mac() {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(pepper, ALGORITHM));
            return mac;
        } catch (GeneralSecurityException unavailable) {
            // HmacSHA256 is required of every Java platform, so no deployment can reach this.
            // Failing loudly beats storing a recovery code protected by something weaker.
            throw new IllegalStateException(ALGORITHM + " is not available on this JVM", unavailable);
        }
    }
}
