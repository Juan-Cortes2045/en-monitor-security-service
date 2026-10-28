package com.energymonitor.security.adapter.in.web.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Size;

/**
 * Body of {@code POST /api/v1/auth/google}: exactly one of the two credentials.
 *
 * @param code    authorization code returned by Google's sign-in popup to the web app
 * @param idToken ID token the mobile app got from the native Google sign-in, issued for the web
 *                client id ({@code webClientId}) so its audience is this server's client
 * @param acceptTerms optional; {@code true} after the client showed the terms and conditions
 *                    (the sign-in answered 428: the account is new or never accepted them)
 */
public record GoogleLoginRequest(@Size(max = 2048) String code,
                                 @Size(max = 4096) String idToken,
                                 Boolean acceptTerms) {

    /** @return whether the terms are accepted with this request */
    public boolean acceptsTerms() {
        return Boolean.TRUE.equals(acceptTerms);
    }

    /** One credential, never both: a request that mixes them is ambiguous. */
    @AssertTrue(message = "send either code or idToken")
    public boolean isOneCredential() {
        return isPresent(code) != isPresent(idToken);
    }

    /** Whether the request comes from the mobile app (ID token) rather than the web popup. */
    public boolean hasIdToken() {
        return isPresent(idToken);
    }

    private static boolean isPresent(String value) {
        return value != null && !value.isBlank();
    }
}
