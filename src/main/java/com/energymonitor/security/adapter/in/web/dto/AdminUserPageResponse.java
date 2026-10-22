package com.energymonitor.security.adapter.in.web.dto;

import com.energymonitor.security.application.result.UserAccountPage;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

@Schema(name = "AdminUserPageResponse", description = "A page of the user directory.")
public record AdminUserPageResponse(List<AdminUserResponse> items, int page, int size,
                                    long totalItems) {

    public static AdminUserPageResponse from(UserAccountPage page) {
        return new AdminUserPageResponse(
                page.items().stream().map(AdminUserResponse::from).toList(),
                page.page(), page.size(), page.totalItems());
    }
}
