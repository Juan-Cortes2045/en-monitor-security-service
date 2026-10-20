package com.energymonitor.security.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.energymonitor.security.application.port.out.PasswordResetTokenHasherPort;
import com.energymonitor.security.application.port.out.RefreshTokenHasherPort;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Contract of the token hasher: deterministic, SHA-256, and never reversible.
 *
 * <p>One adapter serves both token ports, so the behaviour asserted here is what a refresh
 * token and a password-reset token each depend on.
 */
@DisplayName("SHA-256 token hasher")
class Sha256TokenHasherTest {

    private final Sha256TokenHasher hasher = new Sha256TokenHasher();

    @Test
    @DisplayName("the same secret always produces the same hash")
    void isDeterministic() {
        String secret = "un-token-de-refresco-con-256-bits-de-entropia";

        assertThat(hasher.hash(secret)).isEqualTo(hasher.hash(secret));
    }

    @Test
    @DisplayName("different secrets produce different hashes")
    void distinctSecretsDistinctHashes() {
        assertThat(hasher.hash("token-a")).isNotEqualTo(hasher.hash("token-b"));
    }

    @Test
    @DisplayName("the hash is 64 lowercase hex characters, matching the column")
    void hasTheExpectedShape() {
        String hash = hasher.hash("cualquier-secreto");

        assertThat(hash).hasSize(64).matches("[0-9a-f]{64}");
    }

    @Test
    @DisplayName("the digest really is SHA-256 over the UTF-8 bytes")
    void isSha256OfTheInput() throws Exception {
        String secret = "verificacion-independent-del-adapter";
        byte[] expected = MessageDigest.getInstance("SHA-256")
                .digest(secret.getBytes(StandardCharsets.UTF_8));

        // Computed independently here so the test cannot pass by agreeing with a bug in the
        // adapter's own encoding.
        assertThat(hasher.hash(secret)).isEqualTo(HexFormat.of().formatHex(expected));
    }

    @Test
    @DisplayName("the hash does not contain the secret")
    void doesNotLeakTheSecret() {
        String secret = "secreto-que-no-debe-aparecer";

        assertThat(hasher.hash(secret)).doesNotContain(secret);
    }

    @Test
    @DisplayName("refuses a blank secret")
    void refusesBlankSecret() {
        assertThatThrownBy(() -> hasher.hash("  "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("refuses a null secret")
    void refusesNullSecret() {
        assertThatThrownBy(() -> hasher.hash(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("hashes near-identical secrets differently, so it is not a trivial encoding")
    void isNotATrivialEncoding() {
        // A concatenation or truncation bug would collapse these two.
        assertThat(hasher.hash("a".repeat(43))).isNotEqualTo(hasher.hash("a".repeat(44)));
    }

    @Test
    @DisplayName("serves the refresh-token port only")
    void backsTheRefreshTokenPortOnly() {
        // It used to answer for password-reset tokens as well, and deliberately no longer does: a
        // six-digit recovery code has about a million candidates, so a fast digest of it can be
        // reversed from a copy of the table. PepperedHmacResetCodeHasher serves that credential
        // instead, and this assertion exists to catch someone re-widening this adapter.
        RefreshTokenHasherPort refreshPort = new Sha256TokenHasher();

        assertThat(refreshPort.hash("secreto")).hasSize(64);
        assertThat(new Sha256TokenHasher())
                .isNotInstanceOf(PasswordResetTokenHasherPort.class);
    }
}
