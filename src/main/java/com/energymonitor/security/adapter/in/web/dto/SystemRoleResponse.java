package com.energymonitor.security.adapter.in.web.dto;

import com.energymonitor.security.domain.model.SystemRole;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "SystemRoleResponse", description = "A global role that can be granted.")
public record SystemRoleResponse(@Schema(example = "ADMIN") String name, String description) {

    public static SystemRoleResponse from(SystemRole role) {
        return new SystemRoleResponse(role.name(), role.description().orElse(null));
    }
}
