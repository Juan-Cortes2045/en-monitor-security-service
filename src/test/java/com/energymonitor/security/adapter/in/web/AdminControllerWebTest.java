package com.energymonitor.security.adapter.in.web;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.energymonitor.security.application.command.AdministerAccountRoleCommand;
import com.energymonitor.security.application.command.AdministerAccountStatusCommand;
import com.energymonitor.security.application.command.CheckPermissionQuery;
import com.energymonitor.security.application.command.ListUserAccountsQuery;
import com.energymonitor.security.application.exception.SelfAdministrationException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.AdministerUserAccount;
import com.energymonitor.security.application.port.in.CheckPermission;
import com.energymonitor.security.application.port.in.ListUserAccounts;
import com.energymonitor.security.application.result.AuthenticatedUser;
import com.energymonitor.security.application.result.UserAccountPage;
import com.energymonitor.security.application.result.UserAccountSummary;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.PermissionCodes;
import com.energymonitor.security.domain.model.SystemRole;
import com.energymonitor.security.domain.model.UserStatus;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import com.energymonitor.security.infrastructure.JwtTokenIssuer;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Route protection of the administration API: each route requires its own global permission
 * code, checked against the token's subject before the use case runs.
 *
 * <p>The filter chain, JWT validation and error rendering are the real ones; the permission
 * check and the use cases are replaced so each test states exactly which codes the caller holds.
 */
@SpringBootTest
@org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
class AdminControllerWebTest extends JwtKeyedTest {

    private static final String CALLER = "adm0000001";
    private static final String TARGET = "use0000002";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private JwtTokenIssuer tokenIssuer;

    @MockitoBean
    private CheckPermission checkPermission;

    @MockitoBean
    private ListUserAccounts listUserAccounts;

    @MockitoBean
    private AdministerUserAccount administerUserAccount;

    private String bearer() {
        return "Bearer " + tokenIssuer.issue(new AuthenticatedUser(CALLER, "per0000001",
                Email.of("admin@example.com"), UserStatus.ACTIVE, Instant.now(), null));
    }

    /** The caller holds exactly these codes, and nothing else. */
    private void holds(String... codes) {
        Set<String> granted = Set.of(codes);
        given(checkPermission.check(any())).willAnswer(invocation -> {
            CheckPermissionQuery query = invocation.getArgument(0);
            return query.idUser().equals(CALLER) && granted.contains(query.permissionCode());
        });
    }

    private MockHttpServletRequestBuilder changeStatus() {
        return put("/api/v1/admin/users/" + TARGET + "/status")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"status\":\"BLOCKED\"}");
    }

    // ----------------------------------------------------------------- directory

    @Test
    void listsTheDirectoryForACallerHoldingUserRead() throws Exception {
        holds(PermissionCodes.USER_READ);
        given(listUserAccounts.list(any())).willReturn(new UserAccountPage(List.of(
                new UserAccountSummary(TARGET, "ada@example.com", "Ada", "Lovelace",
                        UserStatus.ACTIVE, true, Instant.parse("2026-01-02T03:04:05Z"), null,
                        List.of("ADMIN"))), 0, 20, 1));

        mvc.perform(get("/api/v1/admin/users").param("q", "ada")
                        .header("Authorization", bearer()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(1))
                .andExpect(jsonPath("$.items[0].idUser").value(TARGET))
                .andExpect(jsonPath("$.items[0].status").value("ACTIVE"))
                .andExpect(jsonPath("$.items[0].roles[0]").value("ADMIN"))
                .andExpect(jsonPath("$.items[0].passwordHash").doesNotExist());

        verify(listUserAccounts).list(new ListUserAccountsQuery("ada", 0, 20));
    }

    @Test
    void refusesTheDirectoryToACallerWithoutUserRead() throws Exception {
        holds();

        mvc.perform(get("/api/v1/admin/users").header("Authorization", bearer()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));

        verifyNoInteractions(listUserAccounts);
    }

    @Test
    void refusesTheDirectoryWithoutAToken() throws Exception {
        mvc.perform(get("/api/v1/admin/users"))
                .andExpect(status().isUnauthorized());

        verifyNoInteractions(checkPermission, listUserAccounts);
    }

    @Test
    void checksThePermissionOfTheTokenSubject() throws Exception {
        holds(PermissionCodes.USER_READ);
        given(listUserAccounts.list(any())).willReturn(new UserAccountPage(List.of(), 0, 20, 0));

        mvc.perform(get("/api/v1/admin/users").header("Authorization", bearer()))
                .andExpect(status().isOk());

        verify(checkPermission).check(new CheckPermissionQuery(CALLER, PermissionCodes.USER_READ));
    }

    @Test
    void refusesWhenTheTokenNamesAnAccountThatIsGone() throws Exception {
        willThrow(new UserNotFoundException("gone")).given(checkPermission).check(any());

        mvc.perform(get("/api/v1/admin/users").header("Authorization", bearer()))
                .andExpect(status().isForbidden());
    }

    @Test
    void answersBadRequestForAPageSizeOutOfRange() throws Exception {
        holds(PermissionCodes.USER_READ);

        mvc.perform(get("/api/v1/admin/users").param("size", "500")
                        .header("Authorization", bearer()))
                .andExpect(status().isBadRequest());
    }

    @Test
    void listsTheAssignableRolesForACallerHoldingUserRead() throws Exception {
        holds(PermissionCodes.USER_READ);
        given(listUserAccounts.listAssignableRoles())
                .willReturn(List.of(new SystemRole("rol0000001", "ADMIN", "Administrator", true)));

        mvc.perform(get("/api/v1/admin/roles").header("Authorization", bearer()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].name").value("ADMIN"));
    }

    // ----------------------------------------------------------------- status

    @Test
    void changesTheStatusForACallerHoldingUserManage() throws Exception {
        holds(PermissionCodes.USER_MANAGE);

        mvc.perform(changeStatus().header("Authorization", bearer()))
                .andExpect(status().isNoContent());

        verify(administerUserAccount).changeStatus(new AdministerAccountStatusCommand(
                CALLER, TARGET, UserStatus.BLOCKED, "127.0.0.1"));
    }

    @Test
    void readingTheDirectoryDoesNotAllowChangingAStatus() throws Exception {
        holds(PermissionCodes.USER_READ, PermissionCodes.ROLE_MANAGE);

        mvc.perform(changeStatus().header("Authorization", bearer()))
                .andExpect(status().isForbidden());

        verifyNoInteractions(administerUserAccount);
    }

    @Test
    void answersConflictWhenTheCallerTargetsTheirOwnAccount() throws Exception {
        holds(PermissionCodes.USER_MANAGE);
        willThrow(new SelfAdministrationException("self"))
                .given(administerUserAccount).changeStatus(any());

        mvc.perform(changeStatus().header("Authorization", bearer()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409));
    }

    @Test
    void answersBadRequestForAnUnknownStatus() throws Exception {
        holds(PermissionCodes.USER_MANAGE);

        mvc.perform(put("/api/v1/admin/users/" + TARGET + "/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"DELETED\"}")
                        .header("Authorization", bearer()))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(administerUserAccount);
    }

    @Test
    void answersNotFoundForAMissingAccount() throws Exception {
        holds(PermissionCodes.USER_MANAGE);
        willThrow(new UserNotFoundException("no active user"))
                .given(administerUserAccount).changeStatus(any());

        mvc.perform(changeStatus().header("Authorization", bearer()))
                .andExpect(status().isNotFound());
    }

    // ------------------------------------------------------------------ roles

    @Test
    void grantsAndRevokesRolesForACallerHoldingRoleManage() throws Exception {
        holds(PermissionCodes.ROLE_MANAGE);

        mvc.perform(put("/api/v1/admin/users/" + TARGET + "/roles/ADMIN")
                        .header("Authorization", bearer()))
                .andExpect(status().isNoContent());
        mvc.perform(delete("/api/v1/admin/users/" + TARGET + "/roles/ADMIN")
                        .header("Authorization", bearer()))
                .andExpect(status().isNoContent());

        verify(administerUserAccount).grantRole(
                new AdministerAccountRoleCommand(CALLER, TARGET, "ADMIN", "127.0.0.1"));
        verify(administerUserAccount).revokeRole(
                new AdministerAccountRoleCommand(CALLER, TARGET, "ADMIN", "127.0.0.1"));
    }

    @Test
    void managingStatusesDoesNotAllowChangingRoles() throws Exception {
        holds(PermissionCodes.USER_READ, PermissionCodes.USER_MANAGE);

        mvc.perform(put("/api/v1/admin/users/" + TARGET + "/roles/ADMIN")
                        .header("Authorization", bearer()))
                .andExpect(status().isForbidden());
        mvc.perform(delete("/api/v1/admin/users/" + TARGET + "/roles/ADMIN")
                        .header("Authorization", bearer()))
                .andExpect(status().isForbidden());

        verifyNoInteractions(administerUserAccount);
    }

    @Test
    void anAdminRouteWithoutARuleIsDeniedEvenToAFullAdministrator() throws Exception {
        holds(PermissionCodes.USER_READ, PermissionCodes.USER_MANAGE, PermissionCodes.ROLE_MANAGE);

        mvc.perform(delete("/api/v1/admin/users/" + TARGET).header("Authorization", bearer()))
                .andExpect(status().isForbidden());
    }
}
