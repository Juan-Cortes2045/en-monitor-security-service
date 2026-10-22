package com.energymonitor.security.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Rules of the {@link RefreshToken} generation aggregate: what it refuses to represent, how a
 * generation advances, and why a retired one stays on record.
 */
@DisplayName("RefreshToken")
class RefreshTokenTest {

    private static final String ID = "RFT0000001";
    private static final String SESSION = "USS0000001";
    private static final String HASH = "a".repeat(64);
    private static final Instant CREATED_AT = Instant.parse("2026-05-01T10:00:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2026-05-08T10:00:00Z");
    private static final Instant LATER = Instant.parse("2026-05-01T11:00:00Z");

    private static RefreshToken root() {
        return RefreshToken.root(ID, SESSION, HASH, CREATED_AT, EXPIRES_AT);
    }

    private static RefreshToken childOf(RefreshToken parent) {
        return RefreshToken.childOf(parent, "RFT0000002", "b".repeat(64), LATER,
                LATER.plusSeconds(604800));
    }

    @Nested
    @DisplayName("issuance")
    class Issuance {

        @Test
        @DisplayName("a root generation starts active")
        void rootIsActive() {
            assertThat(root().status()).isEqualTo(RefreshTokenStatus.ACTIVE);
        }

        @Test
        @DisplayName("a root is its own family and has no predecessor")
        void rootIsItsOwnFamily() {
            RefreshToken token = root();

            assertThat(token.familyId()).isEqualTo(ID);
            assertThat(token.parentId()).isEmpty();
            assertThat(token.isRoot()).isTrue();
        }

        @Test
        @DisplayName("a child inherits the family and points at its parent")
        void childCarriesLineage() {
            RefreshToken parent = root();
            RefreshToken child = childOf(parent);

            assertThat(child.familyId()).isEqualTo(parent.familyId());
            assertThat(child.parentId()).contains(ID);
            assertThat(child.idUserSession()).isEqualTo(SESSION);
            assertThat(child.isRoot()).isFalse();
        }

        @Test
        @DisplayName("a child is a distinct generation, not a reuse of its parent")
        void childIsADistinctRecord() {
            RefreshToken parent = root();
            RefreshToken child = childOf(parent);

            assertThat(child.idRefreshToken()).isNotEqualTo(parent.idRefreshToken());
            assertThat(child.tokenHash()).isNotEqualTo(parent.tokenHash());
        }

        @Test
        @DisplayName("a new generation carries no lifecycle stamps")
        void freshHasNoStamps() {
            RefreshToken token = root();

            assertThat(token.rotatedAt()).isEmpty();
            assertThat(token.revokedAt()).isEmpty();
            assertThat(token.revokedReason()).isEmpty();
        }
    }

    @Nested
    @DisplayName("invariants")
    class Invariants {

        @Test
        @DisplayName("refuses a blank hash")
        void refusesBlankHash() {
            assertThatThrownBy(() -> RefreshToken.root(ID, SESSION, "  ", CREATED_AT, EXPIRES_AT))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("tokenHash");
        }

        @Test
        @DisplayName("refuses a null hash")
        void refusesNullHash() {
            assertThatThrownBy(() -> RefreshToken.root(ID, SESSION, null, CREATED_AT, EXPIRES_AT))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("tokenHash");
        }

        @Test
        @DisplayName("refuses a hash wider than the column")
        void refusesOversizedHash() {
            assertThatThrownBy(() -> RefreshToken.root(ID, SESSION, "a".repeat(65), CREATED_AT,
                    EXPIRES_AT))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("tokenHash");
        }

        @Test
        @DisplayName("refuses a blank identifier")
        void refusesBlankIdentifier() {
            assertThatThrownBy(() -> RefreshToken.root("  ", SESSION, HASH, CREATED_AT, EXPIRES_AT))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("idRefreshToken");
        }

        @Test
        @DisplayName("refuses a blank session")
        void refusesBlankSession() {
            assertThatThrownBy(() -> RefreshToken.root(ID, "  ", HASH, CREATED_AT, EXPIRES_AT))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("idUserSession");
        }

        @Test
        @DisplayName("refuses a null status")
        void refusesNullStatus() {
            assertThatThrownBy(() -> new RefreshToken(ID, SESSION, ID, null, HASH, null,
                    CREATED_AT, EXPIRES_AT, null, null, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("status");
        }

        @Test
        @DisplayName("refuses a null creation instant")
        void refusesNullCreatedAt() {
            assertThatThrownBy(() -> RefreshToken.root(ID, SESSION, HASH, null, EXPIRES_AT))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("createdAt");
        }

        @Test
        @DisplayName("refuses an expiry that is not after the issue instant")
        void refusesInvertedWindow() {
            assertThatThrownBy(() -> RefreshToken.root(ID, SESSION, HASH, EXPIRES_AT, CREATED_AT))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("expirationAt must be after createdAt");
        }

        @Test
        @DisplayName("refuses a window whose ends coincide")
        void refusesEmptyWindow() {
            assertThatThrownBy(() -> RefreshToken.root(ID, SESSION, HASH, CREATED_AT, CREATED_AT))
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        @DisplayName("rehydrating enforces the same window as issuing")
        void rehydrationEnforcesTheSameWindow() {
            assertThatThrownBy(() -> new RefreshToken(ID, SESSION, ID, null, HASH,
                    RefreshTokenStatus.ACTIVE, EXPIRES_AT, CREATED_AT, null, null, null))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    @Nested
    @DisplayName("expiry")
    class Expiry {

        @Test
        @DisplayName("is usable one second before expiry")
        void usableBeforeExpiry() {
            assertThat(root().isUsable(EXPIRES_AT.minusSeconds(1))).isTrue();
        }

        @Test
        @DisplayName("is not usable once expiry is reached")
        void notUsableAtExpiry() {
            RefreshToken token = root();

            assertThat(token.isExpired(EXPIRES_AT)).isTrue();
            assertThat(token.isUsable(EXPIRES_AT)).isFalse();
        }
    }

    @Nested
    @DisplayName("rotation")
    class Rotation {

        @Test
        @DisplayName("retires the generation and stamps the instant")
        void rotateRetiresAndStamps() {
            RefreshToken token = root();

            token.rotate(LATER);

            assertThat(token.status()).isEqualTo(RefreshTokenStatus.ROTATED);
            assertThat(token.rotatedAt()).contains(LATER);
        }

        @Test
        @DisplayName("a retired generation is no longer usable")
        void rotatedIsNotUsable() {
            RefreshToken token = root();

            token.rotate(LATER);

            assertThat(token.isUsable(LATER)).isFalse();
        }

        @Test
        @DisplayName("a retired generation is recognisable as a replay")
        void rotatedIsAReplay() {
            RefreshToken token = root();

            assertThat(token.isReplayed()).isFalse();
            token.rotate(LATER);
            assertThat(token.isReplayed()).isTrue();
        }

        @Test
        @DisplayName("a retired generation is kept rather than discarded")
        void rotatedIsStillReadable() {
            // Deleting the predecessor would make its replay look like an unknown token, and
            // the theft would go unnoticed.
            RefreshToken token = root();

            token.rotate(LATER);

            assertThat(token.idRefreshToken()).isEqualTo(ID);
            assertThat(token.tokenHash()).isEqualTo(HASH);
        }

        @Test
        @DisplayName("refuses a second rotation")
        void refusesSecondRotation() {
            RefreshToken token = root();
            token.rotate(LATER);

            assertThatThrownBy(() -> token.rotate(LATER.plusSeconds(60)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("ROTATED");
        }

        @Test
        @DisplayName("refuses a null rotation instant")
        void refusesNullInstant() {
            RefreshToken token = root();

            assertThatThrownBy(() -> token.rotate(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("rotatedAt");
        }

        @Test
        @DisplayName("refuses to rotate a revoked generation")
        void refusesRevoked() {
            RefreshToken token = root();
            token.revoke(LATER, RevocationReason.PASSWORD_CHANGED);

            assertThatThrownBy(() -> token.rotate(LATER.plusSeconds(60)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("REVOKED");
        }

        @Test
        @DisplayName("a refused rotation leaves the generation active")
        void refusedRotationKeepsActive() {
            RefreshToken token = root();
            token.revoke(LATER, RevocationReason.PASSWORD_CHANGED);

            assertThatThrownBy(() -> token.rotate(LATER.plusSeconds(60)))
                    .isInstanceOf(IllegalStateException.class);

            assertThat(token.status()).isEqualTo(RefreshTokenStatus.REVOKED);
            assertThat(token.rotatedAt()).isEmpty();
        }
    }

    @Nested
    @DisplayName("revocation")
    class Revocation {

        @Test
        @DisplayName("records the instant and the reason")
        void revokeRecordsBoth() {
            RefreshToken token = root();

            token.revoke(LATER, RevocationReason.REFRESH_TOKEN_REUSE);

            assertThat(token.status()).isEqualTo(RefreshTokenStatus.REVOKED);
            assertThat(token.revokedAt()).contains(LATER);
            assertThat(token.revokedReason()).contains(RevocationReason.REFRESH_TOKEN_REUSE);
        }

        @Test
        @DisplayName("a revoked generation is no longer usable")
        void revokedIsNotUsable() {
            RefreshToken token = root();

            token.revoke(LATER, RevocationReason.ADMINISTRATIVE);

            assertThat(token.isUsable(LATER)).isFalse();
        }

        @Test
        @DisplayName("a revoked generation is not treated as a replay")
        void revokedIsNotAReplay() {
            // Escalating a plain revocation into a family-wide incident would be wrong: only a
            // spent token proves a second holder.
            RefreshToken token = root();

            token.revoke(LATER, RevocationReason.ADMINISTRATIVE);

            assertThat(token.isReplayed()).isFalse();
        }

        @Test
        @DisplayName("the first revocation is the one that stands")
        void secondRevocationDoesNotOverwrite() {
            RefreshToken token = root();
            token.revoke(LATER, RevocationReason.REFRESH_TOKEN_REUSE);

            token.revoke(LATER.plusSeconds(600), RevocationReason.ADMINISTRATIVE);

            assertThat(token.revokedAt()).contains(LATER);
            assertThat(token.revokedReason()).contains(RevocationReason.REFRESH_TOKEN_REUSE);
        }

        @Test
        @DisplayName("refuses a null instant")
        void refusesNullInstant() {
            RefreshToken token = root();

            assertThatThrownBy(() -> token.revoke(null, RevocationReason.ADMINISTRATIVE))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("revokedAt");
        }

        @Test
        @DisplayName("refuses a null reason")
        void refusesNullReason() {
            RefreshToken token = root();

            assertThatThrownBy(() -> token.revoke(LATER, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("revokedReason");
        }

        @Test
        @DisplayName("refuses to revoke a retired generation, so a spent token stays spent")
        void refusesToRevokeRotated() {
            RefreshToken token = root();
            token.rotate(LATER);

            assertThatThrownBy(() -> token.revoke(LATER.plusSeconds(60),
                    RevocationReason.REFRESH_TOKEN_REUSE))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("rotated");

            assertThat(token.status()).isEqualTo(RefreshTokenStatus.ROTATED);
        }
    }

    @Nested
    @DisplayName("state machine")
    class StateMachine {

        /** A token whose window closed before the reference instant. */
        private RefreshToken aged() {
            return new RefreshToken(ID, SESSION, ID, null, HASH, RefreshTokenStatus.ACTIVE,
                    CREATED_AT.minus(Duration.ofDays(30)),
                    CREATED_AT.minus(Duration.ofDays(23)), null, null, null);
        }

        @Test
        @DisplayName("ACTIVE with a window still open is usable")
        void activeAndNotExpiredIsUsable() {
            assertThat(root().status()).isEqualTo(RefreshTokenStatus.ACTIVE);
            assertThat(root().isUsable(LATER)).isTrue();
        }

        @Test
        @DisplayName("ACTIVE with a window already closed is not usable")
        void activeButExpiredIsNotUsable() {
            assertThat(aged().isUsable(LATER)).isFalse();
        }

        @Test
        @DisplayName("an aged-out token keeps its stored status: expiry is derived, not written")
        void expiryIsDerivedNotPersisted() {
            // Nothing marks it EXPIRED. Restating what the clock already says would need a job
            // to keep in step with time, and no behaviour would depend on it.
            assertThat(aged().status()).isEqualTo(RefreshTokenStatus.ACTIVE);
            assertThat(aged().isExpired(LATER)).isTrue();
        }

        @Test
        @DisplayName("an expired token is not a replay")
        void expiredIsNotAReplay() {
            // A client that was slow must not have its family revoked, or every lagging clock
            // would become a security incident.
            assertThat(aged().isReplayed()).isFalse();
        }

        @Test
        @DisplayName("a retired token is a replay whatever its window says")
        void rotatedIsReplayedEvenWhileNotExpired() {
            RefreshToken token = root();

            token.rotate(LATER);

            assertThat(token.isReplayed()).isTrue();
            assertThat(token.isExpired(LATER)).isFalse();
        }

        @Test
        @DisplayName("a revoked token is neither usable nor a replay")
        void revokedIsInert() {
            RefreshToken token = root();

            token.revoke(LATER, RevocationReason.ADMINISTRATIVE);

            assertThat(token.isUsable(LATER)).isFalse();
            assertThat(token.isReplayed()).isFalse();
        }

        @Test
        @DisplayName("the four combinations map to the four outcomes")
        void theMatrixHolds() {
            // ACTIVE/future -> rotates. ACTIVE/past -> rejected. ROTATED -> replay.
            // REVOKED -> rejected. Exactly one of the four reaches the rotating path.
            assertThat(root().isUsable(LATER)).isTrue();
            assertThat(aged().isUsable(LATER)).isFalse();
            assertThat(root().isReplayed()).isFalse();
            assertThat(aged().isReplayed()).isFalse();
        }
    }

    @Test
    @DisplayName("identity is the generation identifier")
    void equalityIsByIdentifier() {
        RefreshToken one = root();
        RefreshToken other = new RefreshToken(ID, "USS9999999", ID, null, "c".repeat(64),
                RefreshTokenStatus.ACTIVE, CREATED_AT, EXPIRES_AT, null, null, null);

        assertThat(one).isEqualTo(other).hasSameHashCodeAs(other);
    }

    @Test
    @DisplayName("toString carries no hash")
    void toStringLeaksNothing() {
        assertThat(root().toString()).doesNotContain(HASH);
    }
}
