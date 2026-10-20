package com.energymonitor.security.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("AuditLog")
class AuditLogTest {

    private static final String ID = "AUD0000001";
    private static final Instant WHEN = Instant.parse("2026-06-01T18:00:00Z");

    private static User user() {
        return User.register("USR0000001", "PER0000001",
                PasswordHash.of("$2a$10$abcdefghijklmnopqrstuv"),
                Email.of("ana@example.com"),
                Instant.parse("2026-01-15T10:00:00Z"), null);
    }

    @Test
    @DisplayName("records the action it was built with")
    void recordsAction() {
        AuditLog log = new AuditLog(ID, "USR0000001", AuditAction.UPDATE, "Perfil actualizado",
                "192.168.1.10", "energy-monitor-web", WHEN);

        assertThat(log.action()).isEqualTo(AuditAction.UPDATE);
        assertThat(log.idUser()).contains("USR0000001");
        assertThat(log.description()).contains("Perfil actualizado");
        assertThat(log.application()).contains("energy-monitor-web");
        assertThat(log.occurredAt()).isEqualTo(WHEN);
    }

    @Test
    @DisplayName("accepts an absent user when the actor is unknown")
    void acceptsAbsentUser() {
        AuditLog log = new AuditLog(ID, null, AuditAction.DELETE, null, null, null, WHEN);

        assertThat(log.idUser()).isEmpty();
        assertThat(log.description()).isEmpty();
        assertThat(log.ipAddress()).isEmpty();
    }

    @Test
    @DisplayName("login factory records a LOGIN for a known user")
    void loginFactory() {
        AuditLog log = AuditLog.login(ID, user(), "192.168.1.10", WHEN);

        assertThat(log.action()).isEqualTo(AuditAction.LOGIN);
        assertThat(log.idUser()).contains("USR0000001");
        assertThat(log.ipAddress()).contains("192.168.1.10");
    }

    @Test
    @DisplayName("loginFailed factory records a LOGIN_FAILED with no user when unknown")
    void loginFailedFactoryWithoutUser() {
        AuditLog log = AuditLog.loginFailed(ID, null, "10.0.0.1", WHEN);

        assertThat(log.action()).isEqualTo(AuditAction.LOGIN_FAILED);
        assertThat(log.idUser()).isEmpty();
    }

    @Test
    @DisplayName("refuses a null action")
    void refusesNullAction() {
        assertThatThrownBy(() -> new AuditLog(ID, "USR0000001", null, null, null, null, WHEN))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("action");
    }

    @Nested
    @DisplayName("AuditAction")
    class ActionClassification {

        @Test
        @DisplayName("login, login_failed and logout are authentication events")
        void authenticationEvents() {
            assertThat(AuditAction.LOGIN.isAuthenticationEvent()).isTrue();
            assertThat(AuditAction.LOGIN_FAILED.isAuthenticationEvent()).isTrue();
            assertThat(AuditAction.LOGOUT.isAuthenticationEvent()).isTrue();
        }

        @Test
        @DisplayName("create, update and delete are not authentication events")
        void nonAuthenticationEvents() {
            assertThat(AuditAction.CREATE.isAuthenticationEvent()).isFalse();
            assertThat(AuditAction.UPDATE.isAuthenticationEvent()).isFalse();
            assertThat(AuditAction.DELETE.isAuthenticationEvent()).isFalse();
        }

        @Test
        @DisplayName("every constant named in the schema exists")
        void constantsMatchSchema() {
            assertThat(AuditAction.values())
                    .containsExactly(AuditAction.CREATE, AuditAction.UPDATE, AuditAction.DELETE,
                            AuditAction.LOGIN, AuditAction.LOGIN_FAILED, AuditAction.LOGOUT);
        }
    }

    @Test
    @DisplayName("identity is the identifier")
    void equalityIsByIdentifier() {
        AuditLog one = new AuditLog(ID, "USR0000001", AuditAction.LOGIN, null, null, null, WHEN);
        AuditLog other = new AuditLog(ID, "USR9999999", AuditAction.LOGOUT, null, null, null, WHEN);

        assertThat(one).isEqualTo(other).hasSameHashCodeAs(other);
    }
}
