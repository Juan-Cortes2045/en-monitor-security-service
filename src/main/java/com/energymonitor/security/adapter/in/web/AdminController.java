package com.energymonitor.security.adapter.in.web;

import com.energymonitor.security.adapter.in.web.dto.AdminUserPageResponse;
import com.energymonitor.security.adapter.in.web.dto.ApiError;
import com.energymonitor.security.adapter.in.web.dto.ChangeAccountStatusRequest;
import com.energymonitor.security.adapter.in.web.dto.SystemRoleResponse;
import com.energymonitor.security.application.command.AdministerAccountRoleCommand;
import com.energymonitor.security.application.command.AdministerAccountStatusCommand;
import com.energymonitor.security.application.command.ListUserAccountsQuery;
import com.energymonitor.security.application.port.in.AdministerUserAccount;
import com.energymonitor.security.application.port.in.ListUserAccounts;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Platform administration: the user directory, account states and global roles.
 *
 * <p><strong>Nothing is authorized here.</strong> Every route is guarded by a permission code
 * in {@code SecurityFilterChainConfiguration} before it reaches this class: {@code USER.READ}
 * to read, {@code USER.MANAGE} to change an account's state and {@code ROLE.MANAGE} to change
 * its roles. A caller without the code gets 403 and the use case never runs.
 *
 * <p>These are global permissions. They do not open any home: an administrator who is not a
 * member of a home still cannot read it, because the Home Management context decides that on
 * its own owner and member roles.
 */
@RestController
@RequestMapping("/api/v1/admin")
@Tag(name = "Administration", description = "User directory, account states and global roles")
public class AdminController {

    private final ListUserAccounts listUserAccounts;
    private final AdministerUserAccount administerUserAccount;

    public AdminController(ListUserAccounts listUserAccounts,
                           AdministerUserAccount administerUserAccount) {
        this.listUserAccounts = listUserAccounts;
        this.administerUserAccount = administerUserAccount;
    }

    @Operation(summary = "List accounts",
            description = "Active accounts, newest first, optionally filtered by a text matched "
                    + "against the address, name and last name. Requires USER.READ.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "The page of accounts"),
            @ApiResponse(responseCode = "400", description = "Page or size out of range",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "Missing or invalid token",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "The caller lacks USER.READ",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @GetMapping("/users")
    public ResponseEntity<AdminUserPageResponse> listUsers(
            @RequestParam(name = "q", required = false) String text,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        return ResponseEntity.ok(AdminUserPageResponse.from(
                listUserAccounts.list(new ListUserAccountsQuery(text, page, size))));
    }

    @Operation(summary = "List the global roles that can be granted",
            description = "Requires USER.READ.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @GetMapping("/roles")
    public ResponseEntity<List<SystemRoleResponse>> listRoles() {
        return ResponseEntity.ok(listUserAccounts.listAssignableRoles().stream()
                .map(SystemRoleResponse::from).toList());
    }

    @Operation(summary = "Change an account's state",
            description = "Moves another account to ACTIVE, INACTIVE or BLOCKED. Leaving ACTIVE "
                    + "revokes its open sessions. Requires USER.MANAGE.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "State changed"),
            @ApiResponse(responseCode = "400", description = "Missing or unknown status",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "The caller lacks USER.MANAGE",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "404", description = "No such account",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "409", description = "The caller targeted their own "
                    + "account", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    @PutMapping("/users/{idUser}/status")
    public ResponseEntity<Void> changeStatus(@PathVariable String idUser,
                                             @Valid @RequestBody ChangeAccountStatusRequest body,
                                             Authentication authentication,
                                             HttpServletRequest servlet) {
        administerUserAccount.changeStatus(new AdministerAccountStatusCommand(
                authentication.getName(), idUser, body.status(), servlet.getRemoteAddr()));
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Grant a global role",
            description = "Idempotent. Requires ROLE.MANAGE. 404 when the account or an "
                    + "assignable role with that name does not exist; 409 on the caller's own "
                    + "account.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @PutMapping("/users/{idUser}/roles/{roleName}")
    public ResponseEntity<Void> grantRole(@PathVariable String idUser,
                                          @PathVariable String roleName,
                                          Authentication authentication,
                                          HttpServletRequest servlet) {
        administerUserAccount.grantRole(new AdministerAccountRoleCommand(
                authentication.getName(), idUser, roleName, servlet.getRemoteAddr()));
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Revoke a global role",
            description = "Idempotent. Requires ROLE.MANAGE. 404 when the account or the role "
                    + "does not exist; 409 on the caller's own account.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @DeleteMapping("/users/{idUser}/roles/{roleName}")
    public ResponseEntity<Void> revokeRole(@PathVariable String idUser,
                                           @PathVariable String roleName,
                                           Authentication authentication,
                                           HttpServletRequest servlet) {
        administerUserAccount.revokeRole(new AdministerAccountRoleCommand(
                authentication.getName(), idUser, roleName, servlet.getRemoteAddr()));
        return ResponseEntity.noContent().build();
    }
}
