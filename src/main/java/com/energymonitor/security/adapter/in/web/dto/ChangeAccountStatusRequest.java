package com.energymonitor.security.adapter.in.web.dto;

import com.energymonitor.security.domain.model.UserStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

@Schema(name = "ChangeAccountStatusRequest", description = "The state to move the account to.")
public record ChangeAccountStatusRequest(
        @NotNull @Schema(allowableValues = {"ACTIVE", "INACTIVE", "BLOCKED"},
                requiredMode = Schema.RequiredMode.REQUIRED)
        UserStatus status) {
}
