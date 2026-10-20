package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of a password-reset request.
 *
 * @param email the account address whose reset token is requested
 */
public record ForgotPasswordRequest(@NotBlank @Size(max = 255) String email) {
}
