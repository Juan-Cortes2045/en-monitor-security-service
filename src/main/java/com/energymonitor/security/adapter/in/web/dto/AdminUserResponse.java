package com.energymonitor.security.adapter.in.web.dto;

import com.energymonitor.security.application.result.UserAccountSummary;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;
import java.util.List;

@Schema(name = "AdminUserResponse", description = "One account as the user directory shows it.")
public record AdminUserResponse(
        String idUser,
        String email,
        String name,
        String lastName,
        @Schema(allowableValues = {"ACTIVE", "INACTIVE", "BLOCKED"}) String status,
        boolean emailVerified,
        Instant registeredAt,
        Instant lastLoginAt,
        @Schema(description = "Global roles held, sorted", example = "[\"ADMIN\"]")
        List<String> roles) {

    public static AdminUserResponse from(UserAccountSummary summary) {
        return new AdminUserResponse(summary.idUser(), summary.email(), summary.name(),
                summary.lastName(), summary.status().name(), summary.emailVerified(),
                summary.registeredAt(), summary.lastLoginAt(), summary.roles());
    }
}
