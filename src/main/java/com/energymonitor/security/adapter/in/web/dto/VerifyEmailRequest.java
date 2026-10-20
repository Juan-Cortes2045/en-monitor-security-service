package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Body of {@code POST /api/v1/auth/email/verify}.
 */
public record VerifyEmailRequest(
        @NotBlank @Email String email,
        @NotBlank
        @Pattern(regexp = "\\d{6}", message = "must be the six-digit code from the verification email")
        String code) {
}
