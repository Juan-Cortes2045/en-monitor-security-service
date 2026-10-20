package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of {@code POST /api/v1/auth/account/delete}.
 *
 * @param password the current password, confirming the deletion
 */
public record DeleteAccountRequest(@NotBlank @Size(max = 255) String password) {
}
