package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of a logout request.
 *
 * <p>Only the session is named. The owning account is read from the validated access token,
 * and the audit entry for the logout is attributed to the session's persisted owner rather
 * than to anything the caller sends.
 *
 * @param idUserSession the session to revoke
 */
public record LogoutRequest(@NotBlank @Size(max = 10) String idUserSession) {
}
