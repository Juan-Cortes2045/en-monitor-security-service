package com.energymonitor.security.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("PasswordResetToken")
class PasswordResetTokenTest {

    private static final String ID = "PRT0000001";
    private static final String ID_USER = "USR0000001";
    private static final String CLEAR_TOKEN = "secreto-de-recuperacion";
    private static final String HASH =
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    private static final Instant CREATED_AT = Instant.parse("2026-03-01T09:00:00Z");
    private static final Instant EXPIRATION_AT = Instant.parse("2026-03-01T10:00:00Z");

    private static PasswordResetToken token() {
        return PasswordResetToken.issue(ID, ID_USER, CLEAR_TOKEN, HASH, CREATED_AT, EXPIRATION_AT);
    }

    @Test
    @DisplayName("is issued unused and valid before its expiration")
    void isValidWhenFresh() {
        PasswordResetToken token = token();

        assertThat(token.isUsed()).isFalse();
        assertThat(token.isValid(CREATED_AT)).isTrue();
        assertThat(token.isExpired(CREATED_AT)).isFalse();
    }

    @Test
    @DisplayName("is expired once the reference instant reaches the expiration")
    void isExpiredAtTheExpirationInstant() {
        PasswordResetToken token = token();

        assertThat(token.isExpired(EXPIRATION_AT)).isTrue();
        assertThat(token.isExpired(EXPIRATION_AT.plusSeconds(1))).isTrue();
    }

    @Test
    @DisplayName("is no longer valid once expired")
    void isNotValidWhenExpired() {
        PasswordResetToken token = token();

        assertThat(token.isValid(EXPIRATION_AT.plusSeconds(1))).isFalse();
    }

    @Test
    @DisplayName("keeps being valid one second before the expiration")
    void isValidJustBeforeExpiration() {
        PasswordResetToken token = token();

        assertThat(token.isValid(EXPIRATION_AT.minusSeconds(1))).isTrue();
    }

    @Test
    @DisplayName("markUsed consumes the token and it stops being valid")
    void markUsedConsumesTheToken() {
        PasswordResetToken token = token();

        token.markUsed();

        assertThat(token.isUsed()).isTrue();
        assertThat(token.isValid(CREATED_AT)).isFalse();
    }

    @Test
    @DisplayName("a used token cannot be used again")
    void usedTokenCannotBeReused() {
        PasswordResetToken token = token();
        token.markUsed();

        assertThatThrownBy(token::markUsed)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("already been used");
    }

    @Test
    @DisplayName("remaining validity shrinks as time passes and never goes negative")
    void remainingValidityNeverNegative() {
        PasswordResetToken token = token();

        assertThat(token.remainingValidity(CREATED_AT)).isEqualTo(Duration.ofHours(1));
        assertThat(token.remainingValidity(EXPIRATION_AT.plusSeconds(30))).isEqualTo(Duration.ZERO);
    }

    @Test
    @DisplayName("refuses an expiration that is not after the creation")
    void refusesInconsistentWindow() {
        assertThatThrownBy(() -> PasswordResetToken.issue(ID, ID_USER, CLEAR_TOKEN, HASH,
                EXPIRATION_AT, CREATED_AT))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("expirationAt");
    }

    @Test
    @DisplayName("rehydration keeps the used state of a stored token")
    void rehydrationKeepsUsedState() {
        PasswordResetToken token = PasswordResetToken.rehydrate(ID, ID_USER, HASH, CREATED_AT,
                EXPIRATION_AT, true, 0);

        assertThat(token.isUsed()).isTrue();
        assertThat(token.createdAt()).isEqualTo(CREATED_AT);
        assertThat(token.expirationAt()).isEqualTo(EXPIRATION_AT);
    }

    @Test
    @DisplayName("rehydration refuses an expiration that is not after the creation")
    void rehydrationRefusesInconsistentWindow() {
        assertThatThrownBy(() -> PasswordResetToken.rehydrate(ID, ID_USER, HASH, EXPIRATION_AT,
                CREATED_AT, false, 0))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("expirationAt");
    }

    @Test
    @DisplayName("rehydration refuses a window whose ends coincide")
    void rehydrationRefusesEmptyWindow() {
        assertThatThrownBy(() -> PasswordResetToken.rehydrate(ID, ID_USER, HASH, CREATED_AT,
                CREATED_AT, true, 0))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("expirationAt");
    }

    @Test
    @DisplayName("issuing and rehydrating enforce the same validity window")
    void bothFactoriesShareTheWindowRule() {
        Throwable issued = catchThrowable(
                () -> PasswordResetToken.issue(ID, ID_USER, CLEAR_TOKEN, HASH, EXPIRATION_AT,
                        CREATED_AT));
        Throwable rehydrated = catchThrowable(
                () -> PasswordResetToken.rehydrate(ID, ID_USER, HASH, EXPIRATION_AT, CREATED_AT, false, 0));

        assertThat(issued)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("expirationAt must be after createdAt");
        assertThat(rehydrated)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage(issued.getMessage());
    }

    @Test
    @DisplayName("refuses a blank secret to deliver")
    void refusesBlankClearToken() {
        assertThatThrownBy(() -> PasswordResetToken.issue(ID, ID_USER, "   ", HASH, CREATED_AT,
                EXPIRATION_AT))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clearToken");
    }

    @Test
    @DisplayName("refuses a blank hash, because a token that cannot be found is not a token")
    void refusesBlankHash() {
        assertThatThrownBy(() -> PasswordResetToken.issue(ID, ID_USER, CLEAR_TOKEN, "  ",
                CREATED_AT, EXPIRATION_AT))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("resetTokenHash");
    }

    @Test
    @DisplayName("refuses a hash longer than the column it has to fit in")
    void refusesOversizedHash() {
        assertThatThrownBy(() -> PasswordResetToken.rehydrate(ID, ID_USER, "a".repeat(65),
                CREATED_AT, EXPIRATION_AT, false, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("resetTokenHash");
    }

    @Test
    @DisplayName("keeps the hash and the secret side by side without confusing them")
    void holdsTheHashAndTheSecretSeparately() {
        PasswordResetToken token = token();

        assertThat(token.resetTokenHash()).isEqualTo(HASH);
        assertThat(token.clearToken()).contains(CLEAR_TOKEN);
        assertThat(token.resetTokenHash()).doesNotContain(CLEAR_TOKEN);
    }

    @Test
    @DisplayName("a rehydrated token has no secret, because none was ever stored")
    void rehydrationCarriesNoSecret() {
        PasswordResetToken token = PasswordResetToken.rehydrate(ID, ID_USER, HASH, CREATED_AT,
                EXPIRATION_AT, false, 0);

        assertThat(token.clearToken()).isEmpty();
        assertThat(token.resetTokenHash()).isEqualTo(HASH);
    }

    @Test
    @DisplayName("keeps its creation and expiration instants")
    void keepsWindow() {
        PasswordResetToken token = token();

        assertThat(token.createdAt()).isEqualTo(CREATED_AT);
        assertThat(token.expirationAt()).isEqualTo(EXPIRATION_AT);
    }

    @Test
    @DisplayName("does not print the secret in its string form")
    void toStringHidesTheSecret() {
        assertThat(token().toString()).doesNotContain(CLEAR_TOKEN).doesNotContain(HASH);
    }
}
