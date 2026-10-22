package com.energymonitor.security.adapter.in.web.dto;

/**
 * Body of a successful login.
 *
 * <p>Returning tokens is the purpose of this endpoint, so the access and refresh tokens are
 * here by contract. Nothing else is: the account is described by {@link AccountResponse},
 * which has no credential field, and no password hash or persistence detail is present.
 *
 * <h2>Transport of the refresh token</h2>
 *
 * <p>The refresh token is currently returned <strong>in this response body</strong>, not in
 * an HttpOnly cookie. The earlier Javadoc of this record claimed a cookie, which never
 * matched the implementation.
 *
 * <p>Consequences of that choice, recorded so nobody has to infer them:
 *
 * <ul>
 *   <li>The refresh token is a seven-day credential, so a client that stores this body in
 *       script-accessible storage (localStorage, sessionStorage, plain JS state) exposes it
 *       to any XSS on the page. A client that keeps it in memory only narrows the window but
 *       does not remove it.</li>
 *   <li>It is presented back at {@code POST /api/v1/auth/refresh}, in the request body, and
 *       the answer is a new access token and a new secret in the same shape.</li>
 *   <li>Because the token travels in the body and the client sends it back explicitly rather
 *       than relying on an ambient cookie, there is nothing for a cross-site request to ride
 *       on. Disabling CSRF in {@code SecurityFilterChainConfiguration} is correct for that
 *       reason, and would stop being correct if the token ever moved into a cookie.</li>
 * </ul>
 *
 * <p>An HttpOnly cookie was considered and rejected: it would make the token unreachable by
 * script, but it would also make it ambient, and an ambient credential needs CSRF protection on
 * the refresh endpoint in exchange. The exchange is a contract with the frontend, not a
 * detail to settle unilaterally here, so the body was kept and the reasoning is recorded for
 * whoever revisits it.
 *
 * @param accessToken  the signed JWT to send as {@code Authorization: Bearer <token>}
 * @param refreshToken the opaque session token, returned in this body and presented at
 *                     {@code POST /api/v1/auth/refresh}; see the class documentation for the
 *                     transport decision
 * @param tokenType    always {@code Bearer}
 * @param expiresIn    access token lifetime in seconds
 * @param account      the authenticated account
 */
public record LoginResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        AccountResponse account) {
}
