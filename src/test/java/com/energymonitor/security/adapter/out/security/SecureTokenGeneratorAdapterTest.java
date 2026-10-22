package com.energymonitor.security.adapter.out.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.stream.IntStream;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Behaviour of the secure token generator.
 *
 * <p>Reset tokens and session refresh tokens are bearer credentials: whoever holds one can
 * take over the account. These tests therefore check not just that tokens differ, but that
 * the output is unguessable in shape and safe to transport.
 */
class SecureTokenGeneratorAdapterTest {

    /**
     * No column holds a generated token any more: only hashes are persisted. The narrowest
     * place a secret still has to fit is {@code ResetPasswordRequest.resetToken}, the field a
     * redeemed token arrives in.
     */
    private static final int NARROWEST_TOKEN_BUDGET = 100;

    private static final int SAMPLES = 500;

    private final SecureTokenGeneratorAdapter generator = new SecureTokenGeneratorAdapter();

    @Test
    void producesTheSameLengthEveryTime() {
        String reference = generator.generateToken();

        for (int sample = 0; sample < SAMPLES; sample++) {
            assertEquals(reference.length(), generator.generateToken().length(),
                    "A variable length would let an attacker learn the token's entropy");
        }
    }

    @Test
    void producesAValueThatFitsTheNarrowestTokenBudget() {
        assertTrue(generator.generateToken().length() <= NARROWEST_TOKEN_BUDGET);
    }

    @Test
    void usesOnlyCharactersThatSurviveUrlsCookiesAndHeaders() {
        // Base64URL without padding: no '+', '/' or '=' to escape anywhere in the stack.
        String token = generator.generateToken();

        assertTrue(token.matches("[A-Za-z0-9_-]+"),
                "Token contains a character that would need escaping: " + token);
    }

    @Test
    void producesNoCollisionsAcrossManySamples() {
        Set<String> tokens = new HashSet<>();

        for (int sample = 0; sample < SAMPLES; sample++) {
            tokens.add(generator.generateToken());
        }

        assertEquals(SAMPLES, tokens.size(), "A repeated token would let one holder unlock another session");
    }

    @Test
    void doesNotRepeatBackToBack() {
        // A weak or seeded generator tends to repeat within a small window.
        String previous = generator.generateToken();

        for (int sample = 0; sample < 200; sample++) {
            String current = generator.generateToken();
            assertNotEquals(previous, current);
            previous = current;
        }
    }

    @Test
    void drawsFromTheWholeAlphabetRatherThanAShortRun() {
        // Guards against a generator that produces plausible-looking but low-entropy output,
        // for example by incrementing a counter.
        Set<Character> seen = new HashSet<>();

        for (int sample = 0; sample < SAMPLES; sample++) {
            generator.generateToken().chars().forEach(character -> seen.add((char) character));
        }

        assertTrue(seen.size() >= 40,
                "Only " + seen.size() + " distinct characters appeared, which suggests low entropy");
    }

    // ------------------------------------------------------- recovery codes

    @Test
    void producesACodeOfExactlyTheRequestedLength() {
        for (int digits = 1; digits <= 8; digits++) {
            assertEquals(digits, generator.generateNumericCode(digits).length(),
                    "a code of " + digits + " digits came back the wrong length");
        }
    }

    @Test
    void producesOnlyDigits() {
        // The endpoint validates the shape as \\d{6}, so a single stray character would make
        // every code the application issues unredeemable.
        for (int sample = 0; sample < 500; sample++) {
            assertTrue(generator.generateNumericCode(6).matches("\\d{6}"),
                    "a generated code was not six digits");
        }
    }

    @Test
    void neverStartsWithZero() {
        // A leading zero is dropped by number inputs and read as a shorter code, so the first
        // digit is drawn from 1 to 9 instead.
        for (int sample = 0; sample < 500; sample++) {
            assertNotEquals('0', generator.generateNumericCode(6).charAt(0),
                    "a generated code started with a zero");
        }
    }

    @Test
    void reachesEveryDigitSomewhere() {
        Set<Character> seen = new HashSet<>();

        for (int sample = 0; sample < 2_000; sample++) {
            generator.generateNumericCode(6).chars().forEach(character -> seen.add((char) character));
        }

        assertEquals(10, seen.size(),
                "expected all ten digits to appear, saw " + seen);
    }

    @Test
    void doesNotFavourTheDigitsThatModuloBiasWouldInflate() {
        // A digit drawn as byte % 10 would land on 0 six times more often than on 5, because 256
        // leaves six of every 256 values to wrap. With rejection sampling the counts stay even,
        // so a real run of codes should be roughly uniform.
        //
        // Only the five digits after the first are counted: the leading digit is drawn from 1 to 9
        // by design, so including it would report a fifth fewer zeroes than the bias is responsible
        // for and the test would pass or fail for the wrong reason.
        int[] counts = new int[10];

        for (int sample = 0; sample < 40_000; sample++) {
            String code = generator.generateNumericCode(6);
            for (int position = 1; position < 6; position++) {
                counts[code.charAt(position) - '0']++;
            }
        }

        int lowest = IntStream.of(counts).min().orElseThrow();
        int highest = IntStream.of(counts).max().orElseThrow();

        // Far below the 1.25x that modulo bias would produce, far above the noise of a random
        // sample of this size.
        assertTrue(highest < lowest * 1.05,
                "digit counts spread too far to be uniform: " + IntStream.of(counts).boxed()
                        .toList());
    }

    @Test
    void doesNotRepeatItself() {
        // 300 samples out of the 900,000 the generator can produce. A large sample would collide
        // without anything being wrong: by the birthday bound, 5,000 draws from 900,000 are
        // expected to repeat about a dozen times, which says nothing about the generator.
        Set<String> seen = new HashSet<>();

        for (int sample = 0; sample < 300; sample++) {
            seen.add(generator.generateNumericCode(6));
        }

        assertEquals(300, seen.size(), "a generated code came back twice");
    }

    @Test
    void refusesAZeroLengthCode() {
        assertThrows(IllegalArgumentException.class, () -> generator.generateNumericCode(0));
        assertThrows(IllegalArgumentException.class, () -> generator.generateNumericCode(-1));
    }
}
