package com.energymonitor.security.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.energymonitor.security.application.port.out.PasswordResetTokenHasherPort;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("Peppered HMAC hasher for recovery codes")
class PepperedHmacResetCodeHasherTest {

    private static final String PEPPER = "a".repeat(64);
    private static final String USER = "use0000001";
    private static final String OTHER_USER = "use0000002";

    private final PepperedHmacResetCodeHasher hasher =
            new PepperedHmacResetCodeHasher(PEPPER);

    @Nested
    @DisplayName("when hashing a code")
    class Hashing {

        @Test
        @DisplayName("is stable, so a redemption can recompute the same digest")
        void isStable() {
            assertThat(hasher.hash(USER, "123456")).isEqualTo(hasher.hash(USER, "123456"));
        }

        @Test
        @DisplayName("separates codes that differ by one digit")
        void separatesNearIdenticalCodes() {
            assertThat(hasher.hash(USER, "123456")).isNotEqualTo(hasher.hash(USER, "123457"));
        }

        @Test
        @DisplayName("emits lowercase hex, 64 characters, which is what the column holds")
        void emitsFixedWidthLowercaseHex() {
            assertThat(hasher.hash(USER, "123456"))
                    .hasSize(64)
                    .matches("[0-9a-f]{64}");
        }

        @Test
        @DisplayName("is a keyed digest, so the same code under another pepper gives another row")
        void dependsOnThePepper() {
            PepperedHmacResetCodeHasher other =
                    new PepperedHmacResetCodeHasher("b".repeat(64));

            assertThat(hasher.hash(USER, "123456")).isNotEqualTo(other.hash(USER, "123456"));
        }

        @Test
        @DisplayName("is not the plain SHA-256 of the code, which a table dump would reverse")
        void isNotAPlainSha256() {
            String plain = new Sha256TokenHasher().hash("123456");

            assertThat(hasher.hash(USER, "123456")).isNotEqualTo(plain);
        }

        @Test
        @DisplayName("refuses a null or blank code rather than hashing the empty string")
        void refusesBlankCodes() {
            assertThatThrownBy(() -> hasher.hash(USER, null))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> hasher.hash(USER, "  "))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("refuses a blank account, which would hash codes against no account at all")
        void refusesABlankAccount() {
            assertThatThrownBy(() -> hasher.hash(null, "123456"))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> hasher.hash("   ", "123456"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("when two accounts hold the same code")
    class AccountBinding {

        @Test
        @DisplayName("the digests differ, so one account's code cannot resolve another's row")
        void digestsDifferPerAccount() {
            // The property the whole design rests on. Without the account in the hashed material a
            // guessed code would hash to the same value for everyone, and the row it found would be
            // whichever account happened to hold it.
            assertThat(hasher.hash(USER, "123456")).isNotEqualTo(hasher.hash(OTHER_USER, "123456"));
        }

        @Test
        @DisplayName("the separator prevents a shift between account and code")
        void separatorPreventsAShift() {
            // Without ":" these two pairs hash the same string and two different inputs collide.
            assertThat(hasher.hash("ab", "c")).isNotEqualTo(hasher.hash("a", "bc"));
        }

        @Test
        @DisplayName("a code of one account never matches the digest of another")
        void crossAccountCodesNeverMatch() {
            String storedForOther = hasher.hash(OTHER_USER, "123456");
            String presentedForThis = hasher.hash(USER, "123456");

            assertThat(presentedForThis).isNotEqualTo(storedForOther);
        }
    }

    @Nested
    @DisplayName("when the pepper is misconfigured")
    class MissingPepper {

        @Test
        @DisplayName("refuses to start rather than protecting a code with nothing")
        void refusesAMissingPepper() {
            assertThatThrownBy(() -> new PepperedHmacResetCodeHasher(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("security.reset.pepper");
            assertThatThrownBy(() -> new PepperedHmacResetCodeHasher("   "))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("refuses a pepper short enough to be found by trying the plausible ones")
        void refusesAShortPepper() {
            assertThatThrownBy(() -> new PepperedHmacResetCodeHasher("short"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("16");
        }

        @Test
        @DisplayName("ignores surrounding whitespace, since a secret is often pasted")
        void trimsThePepper() {
            PepperedHmacResetCodeHasher padded =
                    new PepperedHmacResetCodeHasher("  " + PEPPER + "  ");

            assertThat(padded.hash(USER, "123456")).isEqualTo(hasher.hash(USER, "123456"));
        }
    }

    @Nested
    @DisplayName("when it serves the port")
    class PortShape {

        @Test
        @DisplayName("answers for the recovery-code port")
        void backsTheResetPort() {
            PasswordResetTokenHasherPort port = hasher;

            assertThat(port.hash(USER, "123456")).hasSize(64);
        }

        @Test
        @DisplayName("spreads distinct codes over distinct digests across the whole space")
        void doesNotCollideOnARealSample() {
            // A thousand codes drawn from the space a six-digit code lives in. Not a proof of
            // injectivity, which HMAC gives by construction, but it would catch a truncation bug
            // that left two codes sharing a stored value.
            long distinct = IntStream.range(0, 1_000)
                    .mapToObj(index -> hasher.hash(USER, String.format("%06d", index)))
                    .distinct()
                    .count();

            assertThat(distinct).isEqualTo(1_000);
        }
    }
}