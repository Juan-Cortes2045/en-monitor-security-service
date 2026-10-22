package com.energymonitor.security.application.command;

/**
 * Input of {@code UpdateUserProfile}: the mutable personal data of a person, plus the optional
 * account email change.
 *
 * <p>{@code null} fields are left unchanged.
 *
 * @param idUser       the account whose profile is edited
 * @param name         new first name, {@code null} to keep
 * @param lastName     new last name, {@code null} to keep
 * @param profileImage new profile image, blank to remove it, {@code null} to keep
 * @param newEmail     delivery hint; the email is never taken from any of the other fields
 * @param ipAddress    optional origin of the request, recorded in the audit trail
 */
public record UpdateUserProfileCommand(String idUser, String name, String lastName,
                                       String profileImage,
                                       String newEmail, String ipAddress) {
}