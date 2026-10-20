package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of {@code POST /api/v1/auth/email/verification/resend}.
 */
public record ResendVerificationRequest(@NotBlank @Size(max = 255) String email) {
}
