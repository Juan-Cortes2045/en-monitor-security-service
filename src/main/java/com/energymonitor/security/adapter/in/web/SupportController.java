package com.energymonitor.security.adapter.in.web;

import com.energymonitor.security.adapter.in.web.dto.SupportContactResponse;
import com.energymonitor.security.api.AdministratorQuery;
import com.energymonitor.security.api.UserProfile;
import com.energymonitor.security.api.UserProfileQuery;
import io.swagger.v3.oas.annotations.Operation;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Who the public support page offers to write to: the platform administrators.
 *
 * <p>Public on purpose - the support page is read before signing in, often because signing in is
 * the problem. It answers only the name and the address of the active administrators (an
 * administrator whose account is blocked or deleted is not offered), nothing else about them.
 */
@RestController
@RequestMapping("/api/v1/support")
public class SupportController {

    private final AdministratorQuery administrators;
    private final UserProfileQuery profiles;

    public SupportController(AdministratorQuery administrators, UserProfileQuery profiles) {
        this.administrators = administrators;
        this.profiles = profiles;
    }

    @Operation(summary = "Support contacts",
            description = "Name and email address of every active administrator, sorted by name, "
                    + "for the support page to write to. Public; an empty list when there is no "
                    + "administrator yet.")
    @GetMapping("/contacts")
    public ResponseEntity<List<SupportContactResponse>> contacts() {
        List<SupportContactResponse> contacts = profiles.findByIds(administrators.activeAdministratorIds())
                .values().stream()
                .filter(profile -> profile.email() != null && !profile.email().isBlank())
                .map(profile -> new SupportContactResponse(fullName(profile), profile.email()))
                .sorted(Comparator.comparing(SupportContactResponse::name, String.CASE_INSENSITIVE_ORDER)
                        .thenComparing(SupportContactResponse::email))
                .toList();
        return ResponseEntity.ok(contacts);
    }

    private static String fullName(UserProfile profile) {
        String name = String.join(" ", Stream.of(profile.name(), profile.lastName())
                .filter(Objects::nonNull).map(String::trim).filter(part -> !part.isEmpty()).toList());
        return name.isEmpty() ? profile.email() : name;
    }
}
