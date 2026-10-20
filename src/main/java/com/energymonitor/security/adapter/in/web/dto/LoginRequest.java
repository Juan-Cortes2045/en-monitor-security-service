package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of a login request.
 *
 * @param email    account address
 * @param password plain-text candidate; it is compared through the password hasher port and
 *                 is never stored, logged or echoed
 */
public record LoginRequest(
        @NotBlank @Size(max = 255) String email,
        @NotBlank @Size(max = 255) String password) {
}
