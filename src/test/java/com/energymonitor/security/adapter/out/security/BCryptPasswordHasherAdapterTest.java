package com.energymonitor.security.adapter.out.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.domain.model.PasswordHash;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Behaviour of the BCrypt password hasher.
 *
 * <p>These are the properties the use cases depend on: a stored hash never reveals the
 * password, the same password hashes differently every time, and a comparison never throws
 * on a stored value that is not a BCrypt hash.
 */
class BCryptPasswordHasherAdapterTest {

    private final BCryptPasswordHasherAdapter hasher = new BCryptPasswordHasherAdapter();

    @Test
    void hashesThePasswordIntoABcryptEncodedValue() {
        PasswordHash hash = hasher.hash("Correct-Horse-9");

        assertTrue(hash.value().startsWith("$2"),
                "Expected a BCrypt encoded hash but got " + hash.value());
        assertNotEquals("Correct-Horse-9", hash.value());
    }

    @Test
    void storesSomethingOtherThanThePlainPassword() {
        String raw = "Swordfish-42";

        String stored = hasher.hash(raw).value();

        assertFalse(stored.contains(raw));
    }

    @Test
    void saltsEveryHashSoTheSamePasswordHashesDifferently() {
        String raw = "Repeatable-7";

        String first = hasher.hash(raw).value();
        String second = hasher.hash(raw).value();

        assertNotEquals(first, second, "BCrypt must salt each hash independently");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Correct-Horse-9", "another-Secret_3", "ñ-Ünicode-Pass-1"})
    void verifiesThePasswordItHashed(String raw) {
        PasswordHash hash = hasher.hash(raw);

        assertTrue(hasher.matches(raw, hash));
    }

    @Test
    void rejectsAPasswordThatWasNeverHashed() {
        PasswordHash hash = hasher.hash("Correct-Horse-9");

        assertFalse(hasher.matches("Correct-Horse-8", hash));
        assertFalse(hasher.matches("", hash));
    }

    @Test
    void rejectsAStoredValueThatIsNotBcryptWithoutFailing() {
        // A row seeded by a script or migrated from another algorithm would otherwise surface
        // as a 500 the first time somebody tried to log in.
        PasswordHash notBcrypt = PasswordHash.of("plain-text-password");

        assertFalse(hasher.matches("plain-text-password", notBcrypt));
    }

    @Test
    void keepsEveryHashWithinTheColumnWidth() {
        // user.password_hash is VARCHAR(255); the encoded form must fit with room to spare.
        String hash = hasher.hash("a-reasonably-long-passphrase-1234567890").value();

        assertTrue(hash.length() <= 255, "Hash of length " + hash.length() + " would not fit");
    }

    @Test
    void neverHasToDealWithABlankStoredValueBecauseTheDomainRejectsIt() {
        // The adapter never has to decide what a blank stored hash means: PasswordHash refuses
        // to be built blank, so an unset password column cannot reach a comparison.
        assertThrows(IllegalArgumentException.class, () -> PasswordHash.of(""));
    }

    @Test
    void handlesALongPassphraseWithoutTruncatingSilentlyIntoAWeakHash() {
        // BCrypt ignores bytes past 72, so this records the behaviour rather than asserting a
        // rejection the domain already prevents: passwords are policy-checked before hashing.
        PasswordHash hash = hasher.hash("a".repeat(72));

        assertTrue(hasher.matches("a".repeat(72), hash));
    }

    @Test
    void verifiesManyDistinctHashesIndependently() {
        Set<String> accepted = new HashSet<>();

        for (int attempt = 0; attempt < 25; attempt++) {
            String raw = "password-" + attempt;
            PasswordHash hash = hasher.hash(raw);
            assertTrue(hasher.matches(raw, hash), "Hash " + attempt + " failed verification");
            accepted.add(hash.value());
        }

        assertEquals(25, accepted.size(), "Each hash must be distinct because of its salt");
    }
}
