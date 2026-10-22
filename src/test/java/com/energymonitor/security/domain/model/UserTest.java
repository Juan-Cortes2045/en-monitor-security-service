package com.energymonitor.security.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("User")
class UserTest {

    private static final String ID_USER = "USR0000001";
    private static final String ID_PERSON = "PER0000001";
    private static final Instant REGISTERED_AT = Instant.parse("2026-01-15T10:00:00Z");

    private static User activeUser() {
        return User.register(ID_USER, ID_PERSON,
                PasswordHash.of("$2a$10$abcdefghijklmnopqrstuv"),
                Email.of("ana@example.com"),
                REGISTERED_AT, null);
    }

    @Nested
    @DisplayName("registration")
    class Registration {

        @Test
        @DisplayName("starts active, unverified, with no failed attempts and no last login")
        void startsInDefaultState() {
            User user = activeUser();

            assertThat(user.status()).isEqualTo(UserStatus.ACTIVE);
            assertThat(user.failedLoginAttempts()).isZero();
            assertThat(user.lastLoginAt()).isEmpty();
            assertThat(user.isEmailVerified()).isFalse();
        }

        @Test
        @DisplayName("keeps the person link, the email and the registration date")
        void keepsIdentityData() {
            User user = activeUser();

            assertThat(user.idUser()).isEqualTo(ID_USER);
            assertThat(user.idPerson()).isEqualTo(ID_PERSON);
            assertThat(user.email().value()).isEqualTo("ana@example.com");
            assertThat(user.dateOfRegistration()).isEqualTo(REGISTERED_AT);
        }

        @Test
        @DisplayName("refuses a negative number of failed attempts")
        void refusesNegativeFailedAttempts() {
            assertThatThrownBy(() -> new User(ID_USER, ID_PERSON,
                    PasswordHash.of("$2a$10$abcdefghijklmnopqrstuv"),
                    Email.of("ana@example.com"), false, REGISTERED_AT,
                    UserStatus.ACTIVE, -1, null, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("failedLoginAttempts");
        }
    }

    @Nested
    @DisplayName("authentication eligibility")
    class Authentication {

        @Test
        @DisplayName("an active user can authenticate")
        void activeUserCanAuthenticate() {
            assertThat(activeUser().canAuthenticate()).isTrue();
        }

        @Test
        @DisplayName("an inactive user cannot authenticate")
        void inactiveUserCannotAuthenticate() {
            User user = activeUser();
            user.deactivate();

            assertThat(user.status()).isEqualTo(UserStatus.INACTIVE);
            assertThat(user.canAuthenticate()).isFalse();
        }

        @Test
        @DisplayName("a blocked user cannot authenticate")
        void blockedUserCannotAuthenticate() {
            User user = activeUser();
            user.block();

            assertThat(user.status()).isEqualTo(UserStatus.BLOCKED);
            assertThat(user.canAuthenticate()).isFalse();
        }
    }

    @Nested
    @DisplayName("state transitions")
    class StateTransitions {

        @Test
        @DisplayName("deactivate then activate returns the account to the active state")
        void canBeDeactivatedAndReactivated() {
            User user = activeUser();

            user.deactivate();
            user.activate();

            assertThat(user.status()).isEqualTo(UserStatus.ACTIVE);
            assertThat(user.canAuthenticate()).isTrue();
        }

        @Test
        @DisplayName("activate clears the failure counter")
        void activateResetsFailedAttempts() {
            User user = activeUser();
            user.incrementFailedLoginAttempts();
            user.incrementFailedLoginAttempts();

            user.activate();

            assertThat(user.failedLoginAttempts()).isZero();
        }

        @Test
        @DisplayName("block then activate returns the account to the active state")
        void blockedUserCanBeRecovered() {
            User user = activeUser();
            user.block();

            user.activate();

            assertThat(user.canAuthenticate()).isTrue();
        }
    }

    @Nested
    @DisplayName("failed login attempts")
    class FailedAttempts {

        @Test
        @DisplayName("increments one at a time")
        void incrementsOneAtATime() {
            User user = activeUser();

            user.incrementFailedLoginAttempts();
            assertThat(user.failedLoginAttempts()).isEqualTo(1);

            user.incrementFailedLoginAttempts();
            user.incrementFailedLoginAttempts();
            assertThat(user.failedLoginAttempts()).isEqualTo(3);
        }

        @Test
        @DisplayName("never becomes negative")
        void neverBecomesNegative() {
            User user = activeUser();

            user.incrementFailedLoginAttempts();
            user.resetFailedLoginAttempts();
            user.incrementFailedLoginAttempts();

            assertThat(user.failedLoginAttempts()).isEqualTo(1);
            assertThat(user.failedLoginAttempts()).isNotNegative();
        }

        @Test
        @DisplayName("reset returns the counter to zero")
        void resetsToZero() {
            User user = activeUser();
            user.incrementFailedLoginAttempts();
            user.incrementFailedLoginAttempts();

            user.resetFailedLoginAttempts();

            assertThat(user.failedLoginAttempts()).isZero();
        }
    }

    @Nested
    @DisplayName("successful login")
    class SuccessfulLogin {

        @Test
        @DisplayName("stamps the instant and clears the failure counter")
        void stampsInstantAndClearsCounter() {
            User user = activeUser();
            user.incrementFailedLoginAttempts();
            user.incrementFailedLoginAttempts();
            Instant loginAt = Instant.parse("2026-02-01T08:30:00Z");

            user.recordSuccessfulLogin(loginAt);

            assertThat(user.lastLoginAt()).contains(loginAt);
            assertThat(user.failedLoginAttempts()).isZero();
        }

        @Test
        @DisplayName("is refused for a blocked account")
        void refusedForBlockedAccount() {
            User user = activeUser();
            user.block();

            assertThatThrownBy(() -> user.recordSuccessfulLogin(Instant.parse("2026-02-01T08:30:00Z")))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("BLOCKED");
        }

        @Test
        @DisplayName("is refused for an inactive account")
        void refusedForInactiveAccount() {
            User user = activeUser();
            user.deactivate();

            assertThatThrownBy(() -> user.recordSuccessfulLogin(Instant.parse("2026-02-01T08:30:00Z")))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("INACTIVE");
        }

        @Test
        @DisplayName("keeps only the most recent instant")
        void keepsMostRecentInstant() {
            User user = activeUser();
            Instant first = Instant.parse("2026-02-01T08:30:00Z");
            Instant second = Instant.parse("2026-02-02T19:00:00Z");

            user.recordSuccessfulLogin(first);
            user.recordSuccessfulLogin(second);

            assertThat(user.lastLoginAt()).contains(second);
        }
    }

    @Nested
    @DisplayName("credentials")
    class Credentials {

        @Test
        @DisplayName("changing the email resets its verified flag")
        void changingEmailUnverifiesIt() {
            User user = activeUser();
            user.verifyEmail();

            user.changeEmail(Email.of("otro@example.com"));

            assertThat(user.email().value()).isEqualTo("otro@example.com");
            assertThat(user.isEmailVerified()).isFalse();
        }

        @Test
        @DisplayName("verifyEmail marks the address as confirmed")
        void verifyEmailMarksConfirmed() {
            User user = activeUser();

            user.verifyEmail();

            assertThat(user.isEmailVerified()).isTrue();
        }

        @Test
        @DisplayName("changing the password replaces the hash")
        void changingPasswordReplacesHash() {
            User user = activeUser();

            user.changePassword(PasswordHash.of("$2a$10$nuevocambiodelhashdeusuario"));

            assertThat(user.passwordHash().value()).isEqualTo("$2a$10$nuevocambiodelhashdeusuario");
        }

        @Test
        @DisplayName("never exposes the hash through toString")
        void hashIsNotLeakedByToString() {
            User user = activeUser();

            assertThat(user.toString()).doesNotContain("$2a$10$abcdefghijklmnopqrstuv");
        }
    }

    @Test
    @DisplayName("identity is the identifier, not the attributes")
    void equalityIsByIdentifier() {
        User one = activeUser();
        User other = User.register(ID_USER, ID_PERSON,
                PasswordHash.of("$2a$10$otrocambiodelhashdeusuario"),
                Email.of("otro@example.com"),
                REGISTERED_AT, null);

        assertThat(one).isEqualTo(other).hasSameHashCodeAs(other);
    }
}
