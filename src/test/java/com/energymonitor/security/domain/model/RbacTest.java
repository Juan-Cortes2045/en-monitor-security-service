package com.energymonitor.security.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("Roles and permissions")
class RbacTest {

    private static final Instant ASSIGNED_AT = Instant.parse("2026-05-01T12:00:00Z");

    private static User user() {
        return User.register("USR0000001", "PER0000001",
                PasswordHash.of("$2a$10$abcdefghijklmnopqrstuv"),
                Email.of("ana@example.com"),
                Instant.parse("2026-01-15T10:00:00Z"), null);
    }

    private static SystemRole adminRole() {
        return new SystemRole("ROL0000001", "ADMIN", "Administrador de la plataforma", true);
    }

    private static Permission readPermission() {
        return new Permission("PERM000001", "READ_HOME", "Leer hogar", "Permite ver un hogar");
    }

    @Nested
    @DisplayName("SystemRole")
    class SystemRoleBehaviour {

        @Test
        @DisplayName("an enabled role can be assigned")
        void enabledRoleCanBeAssigned() {
            SystemRole role = adminRole();

            assertThat(role.isEnabled()).isTrue();
            assertThat(role.canBeAssigned()).isTrue();
        }

        @Test
        @DisplayName("a disabled role cannot be assigned")
        void disabledRoleCannotBeAssigned() {
            SystemRole role = adminRole();

            role.disable();

            assertThat(role.isEnabled()).isFalse();
            assertThat(role.canBeAssigned()).isFalse();
        }

        @Test
        @DisplayName("enabling again restores assignability")
        void enableRestoresAssignability() {
            SystemRole role = adminRole();
            role.disable();

            role.enable();

            assertThat(role.canBeAssigned()).isTrue();
        }

        @Test
        @DisplayName("refuses a blank name")
        void refusesBlankName() {
            assertThatThrownBy(() -> new SystemRole("ROL0000001", "  ", null, true))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("name");
        }

        @Test
        @DisplayName("description is optional")
        void descriptionIsOptional() {
            SystemRole role = new SystemRole("ROL0000001", "USER", null, true);

            assertThat(role.description()).isEmpty();
        }
    }

    @Nested
    @DisplayName("UserSystemRole")
    class UserSystemRoleBehaviour {

        @Test
        @DisplayName("assign links the user to the role and stamps the instant")
        void assignLinksUserToRole() {
            User user = user();
            SystemRole role = adminRole();

            UserSystemRole assignment = UserSystemRole.assign(user, role, ASSIGNED_AT);

            assertThat(assignment.idUser()).isEqualTo(user.idUser());
            assertThat(assignment.idSystemRole()).isEqualTo(role.idSystemRole());
            assertThat(assignment.assignedAt()).isEqualTo(ASSIGNED_AT);
        }

        @Test
        @DisplayName("assign is refused while the role is disabled")
        void assignRefusedForDisabledRole() {
            SystemRole role = adminRole();
            role.disable();

            assertThatThrownBy(() -> UserSystemRole.assign(user(), role, ASSIGNED_AT))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("cannot be assigned");
        }

        @Test
        @DisplayName("the same user and role pair is the same assignment")
        void samePairIsSameAssignment() {
            SystemRole role = adminRole();
            UserSystemRole one = UserSystemRole.assign(user(), role, ASSIGNED_AT);
            UserSystemRole other = new UserSystemRole(user().idUser(), role.idSystemRole(),
                    ASSIGNED_AT.plusSeconds(120));

            assertThat(one).isEqualTo(other).hasSameHashCodeAs(other);
        }

        @Test
        @DisplayName("a different role for the same user is a different assignment")
        void differentRoleIsDifferentAssignment() {
            SystemRole admin = adminRole();
            SystemRole reader = new SystemRole("ROL0000002", "READER", null, true);

            assertThat(UserSystemRole.assign(user(), admin, ASSIGNED_AT))
                    .isNotEqualTo(UserSystemRole.assign(user(), reader, ASSIGNED_AT));
        }

        @Test
        @DisplayName("links reports whether the pair matches")
        void linksReportsMatch() {
            SystemRole role = adminRole();
            UserSystemRole assignment = UserSystemRole.assign(user(), role, ASSIGNED_AT);

            assertThat(assignment.links(user().idUser(), role.idSystemRole())).isTrue();
            assertThat(assignment.links(user().idUser(), "ROL9999999")).isFalse();
        }
    }

    @Nested
    @DisplayName("SystemRolePermission")
    class SystemRolePermissionBehaviour {

        @Test
        @DisplayName("grant links the role to the permission and stamps the instant")
        void grantLinksRoleToPermission() {
            SystemRole role = adminRole();
            Permission permission = readPermission();

            SystemRolePermission grant = SystemRolePermission.grant(role, permission, ASSIGNED_AT);

            assertThat(grant.idSystemRole()).isEqualTo(role.idSystemRole());
            assertThat(grant.idPermission()).isEqualTo(permission.idPermission());
            assertThat(grant.assignedAt()).isEqualTo(ASSIGNED_AT);
        }

        @Test
        @DisplayName("the same role and permission pair is the same grant")
        void samePairIsSameGrant() {
            SystemRole role = adminRole();
            SystemRolePermission one = SystemRolePermission.grant(role, readPermission(), ASSIGNED_AT);
            SystemRolePermission other = new SystemRolePermission(role.idSystemRole(),
                    readPermission().idPermission(), ASSIGNED_AT);

            assertThat(one).isEqualTo(other).hasSameHashCodeAs(other);
        }

        @Test
        @DisplayName("links reports whether the pair matches")
        void linksReportsMatch() {
            SystemRole role = adminRole();
            SystemRolePermission grant = SystemRolePermission.grant(role, readPermission(), ASSIGNED_AT);

            assertThat(grant.links(role.idSystemRole(), readPermission().idPermission())).isTrue();
            assertThat(grant.links("ROL9999999", readPermission().idPermission())).isFalse();
        }

        @Test
        @DisplayName("a permission keeps its code even when renamed")
        void permissionCodeIsStableAcrossRename() {
            Permission permission = readPermission();

            permission.rename("Consultar hogar");

            assertThat(permission.code()).isEqualTo("READ_HOME");
            assertThat(permission.name()).isEqualTo("Consultar hogar");
        }
    }
}
