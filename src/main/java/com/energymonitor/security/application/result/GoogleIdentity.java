package com.energymonitor.security.application.result;

/**
 * Who Google says signed in, read from a verified ID token.
 *
 * @param subject       stable identifier of the Google account ({@code sub})
 * @param emailVerified whether Google verified the address
 * @param givenName     first name, may be null
 * @param familyName    last name, may be null: not every Google account has one
 * @param fullName      display name, may be null
 * @param pictureUrl    profile photo, may be null
 */
public record GoogleIdentity(String subject, String email, boolean emailVerified, String givenName,
                             String familyName, String fullName, String pictureUrl) {
}
