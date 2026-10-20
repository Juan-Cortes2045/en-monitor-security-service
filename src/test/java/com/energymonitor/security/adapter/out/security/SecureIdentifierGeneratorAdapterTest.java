package com.energymonitor.security.adapter.out.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Behaviour of the business identifier generator.
 *
 * <p>Identifiers are primary-key material stored in {@code VARCHAR(10)} columns under a
 * case-insensitive collation, so the length and the lower-case alphabet are part of the
 * contract with the schema rather than an implementation detail.
 */
class SecureIdentifierGeneratorAdapterTest {

    private static final int IDENTIFIER_LENGTH = 10;
    private static final int SAMPLES = 1000;

    private final SecureIdentifierGeneratorAdapter generator =
            new SecureIdentifierGeneratorAdapter();

    @Test
    void producesExactlyTheColumnWidth() {
        for (int sample = 0; sample < SAMPLES; sample++) {
            assertEquals(IDENTIFIER_LENGTH, generator.generate().length(),
                    "An identifier that does not match VARCHAR(10) would be truncated on insert");
        }
    }

    @Test
    void usesOnlyDigitsAndLowerCaseLetters() {
        // Upper case is excluded on purpose: the schema compares case-insensitively, so a
        // mixed-case value would collide with its own lower-case twin.
        for (int sample = 0; sample < SAMPLES; sample++) {
            assertTrue(generator.generate().matches("[0-9a-z]{10}"),
                    "Identifier outside the safe alphabet");
        }
    }

    @Test
    void producesNoCollisionsAcrossManySamples() {
        Set<String> identifiers = new HashSet<>();

        for (int sample = 0; sample < SAMPLES; sample++) {
            identifiers.add(generator.generate());
        }

        assertEquals(SAMPLES, identifiers.size(),
                "A collision would overwrite an existing row through the primary key");
    }

    @Test
    void drawsFromTheWholeAlphabetRatherThanAShortRun() {
        Set<Character> seen = new HashSet<>();

        for (int sample = 0; sample < SAMPLES; sample++) {
            generator.generate().chars().forEach(character -> seen.add((char) character));
        }

        assertTrue(seen.size() >= 30,
                "Only " + seen.size() + " distinct characters appeared, which suggests low entropy");
    }

    @Test
    void staysCaseInsensitivelyUnique() {
        // The same guarantee the collation demands: no two identifiers may differ only by case,
        // which the lower-case alphabet makes impossible by construction.
        Set<String> identifiers = new HashSet<>();

        for (int sample = 0; sample < SAMPLES; sample++) {
            String identifier = generator.generate();
            assertTrue(identifiers.add(identifier.toLowerCase(java.util.Locale.ROOT)));
        }

        assertEquals(SAMPLES, identifiers.size());
    }
}
