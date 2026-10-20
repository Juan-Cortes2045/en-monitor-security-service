package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of a refresh request.
 *
 * <p>The client presents the secret it received at login, in the body rather than in a header.
 * That is a deliberate choice: the credential is sent explicitly by the caller instead of being
 * attached automatically by the browser, so a cross-site request has nothing to ride on and the
 * API stays free of CSRF tokens. The cost is that the secret is reachable by client-side code,
 * which is why the token is only as useful as the client's own storage hygiene.
 *
 * <p>Nothing about the stored generation is accepted here. A client cannot name a family, a
 * parent, a status or a hash: the only thing it can do is present the secret it was given, and
 * the application works out the rest.
 *
 * @param refreshToken the secret issued by a previous login or refresh
 */
public record RefreshRequest(@NotBlank @Size(max = 255) String refreshToken) {
}
