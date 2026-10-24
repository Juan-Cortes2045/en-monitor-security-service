package com.energymonitor.security.adapter.in.web.dto;

/**
 * Body of a successful login.
 *
 * <p>The account is described by {@link AccountResponse}, which has no credential field, and no
 * password hash or persistence detail is present.
 *
 * <h2>Transport of the tokens</h2>
 *
 * <p>A client chooses how it receives them:
 *
 * <ul>
 *   <li><strong>In this body</strong> (the default, used by the mobile app): both tokens are
 *       here, and the refresh token is presented back in the body of
 *       {@code POST /api/v1/auth/refresh}. Nothing ambient travels, so there is nothing for a
 *       cross-site request to ride on.</li>
 *   <li><strong>In HttpOnly cookies</strong> (the web app, which sends
 *       {@code X-Session-Transport: cookie}): {@code accessToken} and {@code refreshToken} are
 *       {@code null} here and the tokens arrive as cookies script cannot read, so an XSS on the
 *       page cannot steal them. They are {@code SameSite=Strict}, and using them also requires a
 *       header a cross-site form or image cannot send ({@code X-Session-Transport} at refresh,
 *       {@code X-Requested-With} at the gateway), which is the CSRF protection the ambient
 *       credential needs. See {@code SessionCookies}.</li>
 * </ul>
 *
 * @param accessToken   the signed JWT to send as {@code Authorization: Bearer <token>}, or
 *                      {@code null} when it was set as a cookie
 * @param refreshToken  the opaque session token presented at {@code POST /api/v1/auth/refresh},
 *                      or {@code null} when it was set as a cookie
 * @param tokenType     always {@code Bearer}
 * @param expiresIn     access token lifetime in seconds
 * @param account       the authenticated account
 * @param idUserSession the session just opened, named at {@code POST /api/v1/auth/logout}; not
 *                      a credential
 */
public record LoginResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        AccountResponse account,
        String idUserSession) {
}
