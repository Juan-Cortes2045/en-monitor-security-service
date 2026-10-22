package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of {@code POST /api/v1/auth/google}.
 *
 * @param code authorization code returned by Google's sign-in popup to the web app
 */
public record GoogleLoginRequest(@NotBlank @Size(max = 2048) String code) {
}
