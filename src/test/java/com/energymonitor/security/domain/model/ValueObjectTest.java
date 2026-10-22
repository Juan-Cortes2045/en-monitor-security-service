package com.energymonitor.security.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("Value objects")
class ValueObjectTest {

    @Nested
    @DisplayName("Email")
    class EmailBehaviour {

        @Test
        @DisplayName("normalises to lower case so uniqueness holds")
        void normalisesToLowerCase() {
            assertThat(Email.of("Ana.Restrepo@Example.COM").value()).isEqualTo("ana.restrepo@example.com");
        }

        @Test
        @DisplayName("trims surrounding whitespace")
        void trimsWhitespace() {
            assertThat(Email.of("  ana@example.com  ").value()).isEqualTo("ana@example.com");
        }

        @Test
        @DisplayName("treats different casing as the same value")
        void equalityIgnoresCasing() {
            assertThat(Email.of("ana@example.com")).isEqualTo(Email.of("ANA@EXAMPLE.COM"));
            assertThat(Email.of("ana@example.com")).hasSameHashCodeAs(Email.of("ANA@EXAMPLE.COM"));
        }

        @Test
        @DisplayName("refuses a blank address")
        void refusesBlank() {
            assertThatThrownBy(() -> Email.of("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("email");
        }

        @Test
        @DisplayName("refuses a string that is not shaped like an address")
        void refusesMalformed() {
            assertThatThrownBy(() -> Email.of("not-an-email"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not a valid address");
            assertThatThrownBy(() -> Email.of("ana@localhost"))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("refuses an address longer than the column")
        void refusesTooLong() {
            assertThatThrownBy(() -> Email.of("a".repeat(250) + "@example.com"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("at most 255");
        }

        @Test
        @DisplayName("measures the length limit after normalising, not before")
        void lengthLimitAppliesToNormalisedValue() {
            String address = "a".repeat(243) + "@example.com";
            String padded = "  " + address + "  ";

            assertThat(address).hasSize(255);
            assertThat(padded).hasSize(259);

            assertThat(Email.of(padded).value()).isEqualTo(address);
        }

        @Test
        @DisplayName("still refuses an address that is too long once normalised")
        void refusesTooLongAfterNormalising() {
            String padded = "  " + "a".repeat(250) + "@example.com  ";

            assertThatThrownBy(() -> Email.of(padded))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("at most 255");
        }

        @Test
        @DisplayName("refuses a null address")
        void refusesNull() {
            assertThatThrownBy(() -> Email.of(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("email");
        }
    }

    @Nested
    @DisplayName("PasswordHash")
    class PasswordHashBehaviour {

        @Test
        @DisplayName("wraps an already-hashed value")
        void wrapsHash() {
            assertThat(PasswordHash.of("$2a$10$abcdefghijklmnopqrstuv").value())
                    .isEqualTo("$2a$10$abcdefghijklmnopqrstuv");
        }

        @Test
        @DisplayName("compares by the wrapped value")
        void equalityByValue() {
            assertThat(PasswordHash.of("$2a$10$unhash")).isEqualTo(PasswordHash.of("$2a$10$unhash"));
            assertThat(PasswordHash.of("$2a$10$unhash")).isNotEqualTo(PasswordHash.of("$2a$10$otro"));
        }

        @Test
        @DisplayName("masks itself in toString so it cannot leak into logs")
        void masksItself() {
            PasswordHash hash = PasswordHash.of("$2a$10$secreto");

            assertThat(hash.toString()).isEqualTo("********").doesNotContain("secreto");
        }

        @Test
        @DisplayName("refuses a blank hash")
        void refusesBlank() {
            assertThatThrownBy(() -> PasswordHash.of("  "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("passwordHash");
        }

        @Test
        @DisplayName("refuses a hash longer than the column")
        void refusesTooLong() {
            assertThatThrownBy(() -> PasswordHash.of("x".repeat(256)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("at most 255");
        }
    }
}
