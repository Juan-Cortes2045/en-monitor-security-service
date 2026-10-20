package com.energymonitor.security.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("Security support model")
class SecuritySupportModelTest {

    @Nested
    @DisplayName("Person")
    class PersonBehaviour {

        private Person person() {
            return new Person("PER0000001", "Ana", "Restrepo");
        }

        @Test
        @DisplayName("keeps the personal data it was given")
        void keepsPersonalData() {
            Person person = person();

            assertThat(person.idPerson()).isEqualTo("PER0000001");
            assertThat(person.name()).isEqualTo("Ana");
            assertThat(person.lastName()).isEqualTo("Restrepo");
        }

        @Test
        @DisplayName("refuses a name longer than the column")
        void refusesAnOverlongName() {
            assertThatThrownBy(() -> new Person("PER0000001", "a".repeat(101), "Restrepo"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("name");
        }

        @Test
        @DisplayName("refuses a missing first name")
        void refusesMissingNames() {
            assertThatThrownBy(() -> new Person("PER0000001", " ", "Restrepo"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("name");
            assertThatThrownBy(() -> new Person("PER0000001", null, "Restrepo"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("name");
        }

        /**
         * An absent last name is legal, not an error: an account created from Google may bring
         * none, and {@code Person} documents it as optional. A last name that is present but
         * empty is a different thing and is still refused.
         */
        @Test
        @DisplayName("accepts an absent last name but not a blank one")
        void lastNameIsOptional() {
            assertThat(new Person("PER0000001", "Ana", null).lastName()).isNull();
            assertThatThrownBy(() -> new Person("PER0000001", "Ana", "  "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("lastName");
        }

        @Test
        @DisplayName("rename replaces the names")
        void renameReplacesNames() {
            Person person = person();

            person.rename("Ana María", "Restrepo Vega");

            assertThat(person.name()).isEqualTo("Ana María");
            assertThat(person.lastName()).isEqualTo("Restrepo Vega");
        }
    }

    @Nested
    @DisplayName("UserConfiguration")
    class UserConfigurationBehaviour {

        @Test
        @DisplayName("defaults turn both notification channels on")
        void defaultsTurnNotificationsOn() {
            UserConfiguration configuration = UserConfiguration.withDefaults("CFG0000001", "USR0000001");

            assertThat(configuration.notifyByEmail()).isTrue();
            assertThat(configuration.notifyByPush()).isTrue();
            assertThat(configuration.hasAnyNotificationChannel()).isTrue();
        }

        @Test
        @DisplayName("customisation fields are optional")
        void customisationFieldsAreOptional() {
            UserConfiguration configuration = UserConfiguration.withDefaults("CFG0000001", "USR0000001");

            assertThat(configuration.colorTheme()).isEmpty();
            assertThat(configuration.language()).isEmpty();
            assertThat(configuration.socialProvider()).isEmpty();
        }

        @Test
        @DisplayName("notification switches can be turned off independently")
        void switchesAreIndependent() {
            UserConfiguration configuration = UserConfiguration.withDefaults("CFG0000001", "USR0000001");

            configuration.setNotifyByPush(false);

            assertThat(configuration.notifyByEmail()).isTrue();
            assertThat(configuration.notifyByPush()).isFalse();
            assertThat(configuration.hasAnyNotificationChannel()).isTrue();
        }

        @Test
        @DisplayName("disabling both channels leaves no notification channel")
        void disablingBothLeavesNoChannel() {
            UserConfiguration configuration = UserConfiguration.withDefaults("CFG0000001", "USR0000001");

            configuration.setNotifyByEmail(false);
            configuration.setNotifyByPush(false);

            assertThat(configuration.hasAnyNotificationChannel()).isFalse();
        }

        @Test
        @DisplayName("theme, language and provider can be set and cleared")
        void customisationCanBeSetAndCleared() {
            UserConfiguration configuration = UserConfiguration.withDefaults("CFG0000001", "USR0000001");

            configuration.changeColorTheme("DARK");
            configuration.changeLanguage("es");
            configuration.linkSocialProvider("GOOGLE");

            assertThat(configuration.colorTheme()).contains("DARK");
            assertThat(configuration.language()).contains("es");
            assertThat(configuration.socialProvider()).contains("GOOGLE");

            configuration.linkSocialProvider(null);

            assertThat(configuration.socialProvider()).isEmpty();
        }
    }

    @Nested
    @DisplayName("PasswordPolicy")
    class PasswordPolicyBehaviour {

        private PasswordPolicy strictPolicy() {
            return new PasswordPolicy("POL0000001", 8, 20, true, true, true, 90);
        }

        @Test
        @DisplayName("accepts a password meeting every rule")
        void acceptsCompliantPassword() {
            assertThat(strictPolicy().isSatisfiedBy("Segura#2026")).isTrue();
        }

        @Test
        @DisplayName("rejects a password below the minimum length")
        void rejectsTooShort() {
            assertThat(strictPolicy().isSatisfiedBy("Aa#1")).isFalse();
        }

        @Test
        @DisplayName("rejects a password above the maximum length")
        void rejectsTooLong() {
            assertThat(strictPolicy().isSatisfiedBy("Aa#1" + "x".repeat(30))).isFalse();
        }

        @Test
        @DisplayName("rejects a password without an upper-case letter when required")
        void rejectsWithoutUppercase() {
            assertThat(strictPolicy().isSatisfiedBy("segura#2026")).isFalse();
        }

        @Test
        @DisplayName("rejects a password without a digit when required")
        void rejectsWithoutDigit() {
            assertThat(strictPolicy().isSatisfiedBy("Segura#xxxx")).isFalse();
        }

        @Test
        @DisplayName("rejects a password without a symbol when required")
        void rejectsWithoutSymbol() {
            assertThat(strictPolicy().isSatisfiedBy("Segura2026")).isFalse();
        }

        @Test
        @DisplayName("rejects null and empty candidates")
        void rejectsNullAndEmpty() {
            assertThat(strictPolicy().isSatisfiedBy(null)).isFalse();
            assertThat(strictPolicy().isSatisfiedBy("")).isFalse();
        }

        @Test
        @DisplayName("skips the rules that are switched off")
        void skipsDisabledRules() {
            PasswordPolicy lenient = new PasswordPolicy("POL0000002", 4, 10, false, false, false, 365);

            assertThat(lenient.isSatisfiedBy("abcd")).isTrue();
        }

        @Test
        @DisplayName("refuses a maximum length below the minimum")
        void refusesInconsistentLengths() {
            assertThatThrownBy(() -> new PasswordPolicy("POL0000001", 10, 8, true, true, true, 90))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("maxLength");
        }

        @Test
        @DisplayName("refuses a non-positive minimum length or expiration")
        void refusesNonPositiveValues() {
            assertThatThrownBy(() -> new PasswordPolicy("POL0000001", 0, 8, true, true, true, 90))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("minLength");
            assertThatThrownBy(() -> new PasswordPolicy("POL0000001", 8, 20, true, true, true, 0))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("expirationDays");
        }
    }

    @Nested
    @DisplayName("SecurityConfiguration")
    class SecurityConfigurationBehaviour {

        @Test
        @DisplayName("keeps the name, the value and the optional description")
        void keepsItsData() {
            SecurityConfiguration configuration = new SecurityConfiguration("SCF0000001",
                    "MAX_LOGIN_ATTEMPTS", "5", "Intentos.maximos antes de bloquear");

            assertThat(configuration.configName()).isEqualTo("MAX_LOGIN_ATTEMPTS");
            assertThat(configuration.configValue()).isEqualTo("5");
            assertThat(configuration.description()).contains("Intentos.maximos antes de bloquear");
        }

        @Test
        @DisplayName("changeValue replaces the value")
        void changeValueReplacesValue() {
            SecurityConfiguration configuration = new SecurityConfiguration("SCF0000001",
                    "MAX_LOGIN_ATTEMPTS", "5", null);

            configuration.changeValue("3");

            assertThat(configuration.configValue()).isEqualTo("3");
        }

        @Test
        @DisplayName("refuses a blank name or value")
        void refusesBlankRequiredFields() {
            assertThatThrownBy(() -> new SecurityConfiguration("SCF0000001", " ", "5", null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("configName");
            assertThatThrownBy(() -> new SecurityConfiguration("SCF0000001", "NAME", "  ", null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("configValue");
        }
    }

    @Nested
    @DisplayName("LoginErrorLog")
    class LoginErrorLogBehaviour {

        private static final Instant WHEN = Instant.parse("2026-07-01T11:00:00Z");

        @Test
        @DisplayName("userNotFound factory leaves the user absent")
        void userNotFoundHasNoUser() {
            LoginErrorLog log = LoginErrorLog.userNotFound("LER0000001", "10.0.0.1", WHEN);

            assertThat(log.errorType()).isEqualTo(LoginErrorType.USER_NOT_FOUND);
            assertThat(log.idUser()).isEmpty();
        }

        @Test
        @DisplayName("a known-account error requires a user")
        void knownAccountErrorRequiresUser() {
            assertThatThrownBy(() -> new LoginErrorLog("LER0000001", null,
                    LoginErrorType.ACCOUNT_BLOCKED, null, null, WHEN))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("ACCOUNT_BLOCKED");
        }

        @Test
        @DisplayName("a known-account error keeps the user reference")
        void knownAccountErrorKeepsUser() {
            LoginErrorLog log = new LoginErrorLog("LER0000001", "USR0000001",
                    LoginErrorType.INVALID_PASSWORD, "Contrasena incorrecta", "10.0.0.1", WHEN);

            assertThat(log.idUser()).contains("USR0000001");
            assertThat(log.description()).contains("Contrasena incorrecta");
            assertThat(log.occurredAt()).isEqualTo(WHEN);
        }

        @Test
        @DisplayName("every constant named in the schema exists")
        void constantsMatchSchema() {
            assertThat(LoginErrorType.values())
                    .containsExactly(LoginErrorType.INVALID_PASSWORD, LoginErrorType.USER_NOT_FOUND,
                            LoginErrorType.ACCOUNT_BLOCKED, LoginErrorType.ACCOUNT_INACTIVE);
        }
    }

    @Nested
    @DisplayName("UserStatus")
    class UserStatusBehaviour {

        @Test
        @DisplayName("only ACTIVE allows authentication")
        void onlyActiveAllowsAuthentication() {
            assertThat(UserStatus.ACTIVE.allowsAuthentication()).isTrue();
            assertThat(UserStatus.INACTIVE.allowsAuthentication()).isFalse();
            assertThat(UserStatus.BLOCKED.allowsAuthentication()).isFalse();
        }

        @Test
        @DisplayName("every constant named in the schema exists")
        void constantsMatchSchema() {
            assertThat(UserStatus.values())
                    .containsExactly(UserStatus.ACTIVE, UserStatus.INACTIVE, UserStatus.BLOCKED);
        }
    }
}
