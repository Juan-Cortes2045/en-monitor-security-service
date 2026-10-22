package com.energymonitor.security.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("UserSession")
class UserSessionTest {

    private static final String ID = "USS0000001";
    private static final String ID_USER = "USR0000001";
    private static final Instant CREATED_AT = Instant.parse("2026-04-01T07:00:00Z");
    private static final Instant EXPIRATION_AT = Instant.parse("2026-04-01T15:00:00Z");
    private static final Instant ONE_HOUR_LATER = CREATED_AT.plusSeconds(3600);

    private static UserSession openSession() {
        return UserSession.open(ID, ID_USER, CREATED_AT, EXPIRATION_AT,
                "192.168.1.10", "Mozilla/5.0");
    }

    @Nested
    @DisplayName("fresh session")
    class Fresh {

        @Test
        @DisplayName("is active, not revoked and not closed")
        void isActiveWhenOpen() {
            UserSession session = openSession();

            assertThat(session.isActive(CREATED_AT)).isTrue();
            assertThat(session.isRevoked()).isFalse();
            assertThat(session.closedAt()).isEmpty();
        }

        @Test
        @DisplayName("keeps its client data")
        void keepsClientData() {
            UserSession session = openSession();

            assertThat(session.idUser()).isEqualTo(ID_USER);
            assertThat(session.ipAddress()).contains("192.168.1.10");
            assertThat(session.userAgent()).contains("Mozilla/5.0");
        }
    }

    @Nested
    @DisplayName("expiration")
    class Expiration {

        @Test
        @DisplayName("is active one second before the expiration")
        void activeJustBeforeExpiration() {
            assertThat(openSession().isActive(EXPIRATION_AT.minusSeconds(1))).isTrue();
        }

        @Test
        @DisplayName("is not active once the expiration is reached")
        void inactiveAtExpiration() {
            UserSession session = openSession();

            assertThat(session.isExpired(EXPIRATION_AT)).isTrue();
            assertThat(session.isActive(EXPIRATION_AT)).isFalse();
        }
    }

    @Nested
    @DisplayName("revocation")
    class Revocation {

        @Test
        @DisplayName("a revoked session is never valid")
        void revokedSessionIsNotActive() {
            UserSession session = openSession();

            session.revoke(CREATED_AT.plusSeconds(120), RevocationReason.ADMINISTRATIVE);

            assertThat(session.isRevoked()).isTrue();
            assertThat(session.isActive(CREATED_AT)).isFalse();
        }

        @Test
        @DisplayName("revoking twice keeps it revoked")
        void revokeIsIdempotent() {
            UserSession session = openSession();

            session.revoke(CREATED_AT.plusSeconds(120), RevocationReason.ADMINISTRATIVE);
            session.revoke(CREATED_AT.plusSeconds(600), RevocationReason.PASSWORD_CHANGED);

            assertThat(session.isRevoked()).isTrue();
        }

        @Test
        @DisplayName("revoking records the instant it happened")
        void revokeStampsInstant() {
            UserSession session = openSession();
            Instant revokedAt = CREATED_AT.plusSeconds(300);

            session.revoke(revokedAt, RevocationReason.ADMINISTRATIVE);

            assertThat(session.revokedAt()).contains(revokedAt);
        }

        @Test
        @DisplayName("revoking records why it happened")
        void revokeStampsReason() {
            UserSession session = openSession();

            session.revoke(CREATED_AT.plusSeconds(120), RevocationReason.REFRESH_TOKEN_REUSE);

            assertThat(session.revokedReason()).contains(RevocationReason.REFRESH_TOKEN_REUSE);
        }

        @Test
        @DisplayName("the first revocation is the one that stands")
        void secondRevocationDoesNotOverwriteTheRecord() {
            UserSession session = openSession();
            Instant firstRevocation = CREATED_AT.plusSeconds(120);

            session.revoke(firstRevocation, RevocationReason.REFRESH_TOKEN_REUSE);
            session.revoke(CREATED_AT.plusSeconds(900), RevocationReason.ADMINISTRATIVE);

            // A later revocation must not rewrite when the problem was first detected.
            assertThat(session.revokedAt()).contains(firstRevocation);
            assertThat(session.revokedReason()).contains(RevocationReason.REFRESH_TOKEN_REUSE);
        }

        @Test
        @DisplayName("revoking does not close the session")
        void revokeDoesNotCloseTheSession() {
            UserSession session = openSession();

            session.revoke(CREATED_AT.plusSeconds(120), RevocationReason.PASSWORD_CHANGED);

            // A revoked session and a closed one must stay distinguishable when read back.
            assertThat(session.closedAt()).isEmpty();
        }

        @Test
        @DisplayName("an open session carries no revocation record")
        void freshSessionHasNoRevocationRecord() {
            UserSession session = openSession();

            assertThat(session.revokedAt()).isEmpty();
            assertThat(session.revokedReason()).isEmpty();
        }

        @Test
        @DisplayName("refuses a revocation without an instant")
        void revokeRefusesNullInstant() {
            UserSession session = openSession();

            assertThatThrownBy(() -> session.revoke(null, RevocationReason.ADMINISTRATIVE))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("revokedAt");
        }

        @Test
        @DisplayName("refuses a revocation without a reason")
        void revokeRefusesNullReason() {
            UserSession session = openSession();

            assertThatThrownBy(() -> session.revoke(CREATED_AT, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("revokedReason");
        }

        @Test
        @DisplayName("a rejected revocation leaves the session untouched")
        void rejectedRevocationChangesNothing() {
            UserSession session = openSession();

            assertThatThrownBy(() -> session.revoke(null, RevocationReason.ADMINISTRATIVE))
                    .isInstanceOf(IllegalArgumentException.class);

            assertThat(session.isRevoked()).isFalse();
            assertThat(session.isActive(CREATED_AT)).isTrue();
        }

        @Test
        @DisplayName("a closed session can still be revoked, because revocation is independent")
        void closedSessionCanStillBeRevoked() {
            UserSession session = openSession();
            session.close(CREATED_AT.plusSeconds(60));

            session.revoke(CREATED_AT.plusSeconds(120), RevocationReason.PASSWORD_CHANGED);

            assertThat(session.isRevoked()).isTrue();
            assertThat(session.revokedReason()).contains(RevocationReason.PASSWORD_CHANGED);
            assertThat(session.closedAt()).contains(CREATED_AT.plusSeconds(60));
        }
    }

    @Nested
    @DisplayName("closure")
    class Closure {

        @Test
        @DisplayName("closing stamps the instant and ends the session")
        void closeStampsInstant() {
            UserSession session = openSession();
            Instant closedAt = Instant.parse("2026-04-01T09:00:00Z");

            session.close(closedAt);

            assertThat(session.closedAt()).contains(closedAt);
            assertThat(session.isActive(closedAt)).isFalse();
        }

        @Test
        @DisplayName("a closed session stays invalid even before its expiration")
        void closedSessionIsNotActive() {
            UserSession session = openSession();
            session.close(CREATED_AT.plusSeconds(60));

            assertThat(session.isActive(ONE_HOUR_LATER)).isFalse();
        }

        @Test
        @DisplayName("closing does not mark the session as revoked")
        void closeDoesNotRevoke() {
            UserSession session = openSession();

            session.close(CREATED_AT.plusSeconds(60));

            // This is what separates a logout from a compromise.
            assertThat(session.isRevoked()).isFalse();
            assertThat(session.revokedAt()).isEmpty();
            assertThat(session.revokedReason()).isEmpty();
        }

        @Test
        @DisplayName("the first closure is the one that stands")
        void closeIsIdempotent() {
            UserSession session = openSession();
            Instant firstClose = CREATED_AT.plusSeconds(60);

            session.close(firstClose);
            session.close(CREATED_AT.plusSeconds(900));

            // A repeated logout must not move the recorded departure time.
            assertThat(session.closedAt()).contains(firstClose);
        }

        @Test
        @DisplayName("refuses a closure without an instant")
        void closeRefusesNullInstant() {
            UserSession session = openSession();

            assertThatThrownBy(() -> session.close(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("instant");
        }
    }

    @Nested
    @DisplayName("rotation")
    class Rotation {

        private static final Instant ROTATED_AT = Instant.parse("2026-04-01T09:00:00Z");
        private static final Instant NEW_EXPIRATION = Instant.parse("2026-04-01T17:00:00Z");

        @Test
        @DisplayName("replaces the expiration")
        void rotatesExpiration() {
            UserSession session = openSession();

            session.rotate(NEW_EXPIRATION, ROTATED_AT);

            assertThat(session.expirationAt()).isEqualTo(NEW_EXPIRATION);
        }

        @Test
        @DisplayName("keeps the session identity, so it is still the same login")
        void keepsIdentity() {
            UserSession session = openSession();

            session.rotate(NEW_EXPIRATION, ROTATED_AT);

            assertThat(session.idUserSession()).isEqualTo(ID);
            assertThat(session).isEqualTo(openSession());
        }

        @Test
        @DisplayName("keeps the owning user")
        void keepsOwner() {
            UserSession session = openSession();

            session.rotate(NEW_EXPIRATION, ROTATED_AT);

            assertThat(session.idUser()).isEqualTo(ID_USER);
        }

        @Test
        @DisplayName("keeps the original creation instant, not the rotation instant")
        void keepsOriginalCreationInstant() {
            UserSession session = openSession();

            session.rotate(NEW_EXPIRATION, ROTATED_AT);

            // Moving this would make the session's age unrecoverable and would let a client
            // slide the window forward without it being visible.
            assertThat(session.createdAt()).isEqualTo(CREATED_AT);
        }

        @Test
        @DisplayName("keeps the recorded client data")
        void keepsClientData() {
            UserSession session = openSession();

            session.rotate(NEW_EXPIRATION, ROTATED_AT);

            assertThat(session.ipAddress()).contains("192.168.1.10");
            assertThat(session.userAgent()).contains("Mozilla/5.0");
        }

        @Test
        @DisplayName("leaves the session active")
        void staysActive() {
            UserSession session = openSession();

            session.rotate(NEW_EXPIRATION, ROTATED_AT);

            assertThat(session.isActive(ROTATED_AT)).isTrue();
            assertThat(session.isRevoked()).isFalse();
            assertThat(session.closedAt()).isEmpty();
        }

        @Test
        @DisplayName("may shorten the window as well as extend it")
        void mayShortenTheWindow() {
            UserSession session = openSession();
            Instant shorter = Instant.parse("2026-04-01T10:00:00Z");

            session.rotate(shorter, ROTATED_AT);

            assertThat(session.expirationAt()).isEqualTo(shorter);
        }

        @Test
        @DisplayName("refuses a null expiration")
        void refusesNullExpiration() {
            UserSession session = openSession();

            assertThatThrownBy(() -> session.rotate(null, ROTATED_AT))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("refuses a null rotation instant")
        void refusesNullRotatedAt() {
            UserSession session = openSession();

            assertThatThrownBy(() -> session.rotate(NEW_EXPIRATION, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("rotatedAt");
        }

        @Test
        @DisplayName("refuses a new expiry that is not after the rotation")
        void refusesInvertedNewWindow() {
            UserSession session = openSession();

            assertThatThrownBy(() -> session.rotate(ROTATED_AT, ROTATED_AT))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("expirationAt must be after createdAt");
        }

        @Test
        @DisplayName("refuses to rotate a revoked session")
        void refusesRevokedSession() {
            UserSession session = openSession();
            session.revoke(CREATED_AT.plusSeconds(60), RevocationReason.REFRESH_TOKEN_REUSE);

            assertThatThrownBy(() -> session.rotate(NEW_EXPIRATION, ROTATED_AT))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("revoked");
        }

        @Test
        @DisplayName("refuses to rotate a closed session")
        void refusesClosedSession() {
            UserSession session = openSession();
            session.close(CREATED_AT.plusSeconds(60));

            assertThatThrownBy(() -> session.rotate(NEW_EXPIRATION, ROTATED_AT))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("closed");
        }

        @Test
        @DisplayName("refuses to rotate an expired session instead of resurrecting it")
        void refusesExpiredSession() {
            UserSession session = openSession();

            // Sliding the window of a login that should be over is exactly what this guards.
            assertThatThrownBy(() -> session.rotate(EXPIRATION_AT.plusSeconds(3600), EXPIRATION_AT))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("expired");
        }

        @Test
        @DisplayName("a refused rotation leaves the previous window in place")
        void refusedRotationKeepsPreviousExpiration() {
            UserSession session = openSession();
            session.close(CREATED_AT.plusSeconds(60));

            assertThatThrownBy(() -> session.rotate(NEW_EXPIRATION, ROTATED_AT))
                    .isInstanceOf(IllegalStateException.class);

            assertThat(session.expirationAt()).isEqualTo(EXPIRATION_AT);
        }
    }

    @Nested
    @DisplayName("lifecycle state")
    class LifecycleState {

        @Test
        @DisplayName("an untouched session is active")
        void openIsActive() {
            assertThat(openSession().isActive(CREATED_AT)).isTrue();
        }

        @Test
        @DisplayName("a closed session is inactive but not revoked")
        void closedIsInactiveNotRevoked() {
            UserSession session = openSession();
            session.close(CREATED_AT.plusSeconds(60));

            assertThat(session.isActive(CREATED_AT.plusSeconds(120))).isFalse();
            assertThat(session.isRevoked()).isFalse();
        }

        @Test
        @DisplayName("a revoked session is inactive and carries no closure")
        void revokedIsInactiveNotClosed() {
            UserSession session = openSession();
            session.revoke(CREATED_AT.plusSeconds(60), RevocationReason.ADMINISTRATIVE);

            assertThat(session.isActive(CREATED_AT.plusSeconds(120))).isFalse();
            assertThat(session.closedAt()).isEmpty();
        }

        @Test
        @DisplayName("an expired session is inactive and untouched otherwise")
        void expiredIsInactive() {
            UserSession session = openSession();

            assertThat(session.isActive(EXPIRATION_AT)).isFalse();
            assertThat(session.isRevoked()).isFalse();
            assertThat(session.closedAt()).isEmpty();
        }

        @Test
        @DisplayName("a session that was both revoked and closed keeps both facts")
        void revokedAndClosedAreIndependent() {
            UserSession session = openSession();
            session.revoke(CREATED_AT.plusSeconds(60), RevocationReason.PASSWORD_CHANGED);
            session.close(CREATED_AT.plusSeconds(90));

            assertThat(session.isRevoked()).isTrue();
            assertThat(session.closedAt()).contains(CREATED_AT.plusSeconds(90));
            assertThat(session.revokedAt()).contains(CREATED_AT.plusSeconds(60));
            assertThat(session.isActive(CREATED_AT.plusSeconds(120))).isFalse();
        }
    }

    @Test
    @DisplayName("refuses an expiration that is not after the creation")
    void refusesInvertedWindow() {
        assertThatThrownBy(() -> UserSession.open(ID, ID_USER, EXPIRATION_AT, CREATED_AT, null, null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("expirationAt must be after createdAt");
    }

    @Test
    @DisplayName("refuses a window whose ends coincide")
    void refusesEmptyWindow() {
        assertThatThrownBy(() -> UserSession.open(ID, ID_USER, CREATED_AT, CREATED_AT, null, null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("expirationAt must be after createdAt");
    }

    @Test
    @DisplayName("rehydrating enforces the same window as opening")
    void rehydrationEnforcesTheSameWindow() {
        assertThatThrownBy(() -> new UserSession(ID, ID_USER, EXPIRATION_AT, CREATED_AT,
                null, null, false, null, null, null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("expirationAt must be after createdAt");
    }

    @Test
    @DisplayName("a session is expired the moment it is created when the window is minimal")
    void minimalWindowIsStillValidState() {
        UserSession session = UserSession.open(ID, ID_USER, CREATED_AT,
                CREATED_AT.plusSeconds(1), null, null);

        assertThat(session.isActive(CREATED_AT)).isTrue();
        assertThat(session.isExpired(CREATED_AT.plusSeconds(1))).isTrue();
    }

    @Test
    @DisplayName("client data may be absent")
    void clientDataIsOptional() {
        UserSession session = UserSession.open(ID, ID_USER, CREATED_AT, EXPIRATION_AT, null, null);

        assertThat(session.ipAddress()).isEmpty();
        assertThat(session.userAgent()).isEmpty();
        assertThat(session.isActive(CREATED_AT)).isTrue();
    }

    @Test
    @DisplayName("identity is the session identifier")
    void equalityIsByIdentifier() {
        UserSession one = openSession();
        UserSession other = new UserSession(ID, "USR9999999", CREATED_AT, EXPIRATION_AT,
                null, null, false, null, null, null);

        assertThat(one).isEqualTo(other).hasSameHashCodeAs(other);
    }
}
