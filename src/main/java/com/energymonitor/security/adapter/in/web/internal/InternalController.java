package com.energymonitor.security.adapter.in.web.internal;

import com.energymonitor.security.adapter.in.web.dto.PermissionsResponse;
import com.energymonitor.security.api.AdministratorQuery;
import com.energymonitor.security.api.UserProfile;
import com.energymonitor.security.api.UserProfileQuery;
import com.energymonitor.security.application.port.in.CheckPermission;
import io.swagger.v3.oas.annotations.Hidden;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * What energy-monitor-backend asks this service while it serves its own requests: the permissions
 * of a caller, the names and addresses of accounts, and who the administrators are.
 *
 * <p>Only the backend reaches these routes; the filter chain of {@code InternalApiConfiguration}
 * checks its network and token before this class runs. They are left out of the published API
 * description.
 */
@Hidden
@RestController
@RequestMapping("/internal")
public class InternalController {

    private final CheckPermission checkPermission;
    private final UserProfileQuery profiles;
    private final AdministratorQuery administrators;

    public InternalController(CheckPermission checkPermission, UserProfileQuery profiles,
                              AdministratorQuery administrators) {
        this.checkPermission = checkPermission;
        this.profiles = profiles;
        this.administrators = administrators;
    }

    /**
     * @param idUser the account
     * @return its permission codes, empty when it cannot sign in; 404 when no active account has
     *         that identifier
     */
    @GetMapping("/users/{idUser}/permissions")
    public PermissionsResponse permissions(@PathVariable String idUser) {
        return PermissionsResponse.of(checkPermission.listGrantedCodes(idUser));
    }

    /**
     * One call for a whole list, so a list of home members costs one request and not one per
     * member.
     *
     * @param request the accounts to look up
     * @return the profile of every active account among them; the others are absent
     */
    @PostMapping("/users/profiles")
    public ProfilesResponse profiles(@Valid @RequestBody ProfilesRequest request) {
        return new ProfilesResponse(List.copyOf(profiles.findByIds(request.userIds()).values()));
    }

    /**
     * @return the accounts holding the {@code ADMIN} role that can sign in
     */
    @GetMapping("/administrators")
    public AdministratorsResponse administrators() {
        return new AdministratorsResponse(administrators.activeAdministratorIds());
    }

    /** @param userIds at most 500, duplicates allowed */
    public record ProfilesRequest(@NotNull @Size(max = 500) List<String> userIds) {
    }

    /** @param profiles the accounts found */
    public record ProfilesResponse(List<UserProfile> profiles) {
    }

    /** @param userIds the administrators */
    public record AdministratorsResponse(List<String> userIds) {
    }
}
