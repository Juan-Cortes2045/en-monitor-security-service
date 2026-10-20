package com.energymonitor.security.application.command;

/**
 * Input of {@code RegisterUser}: the data needed to create the {@code Person} and its
 * {@code User} account.
 *
 * @param email        account address
 * @param rawPassword  plain-text password, validated against the policy and hashed by the
 *                     hasher port; never stored
 * @param name         first name, required
 * @param lastName     last name, required
 * @param profileImage optional
 * @param ipAddress    optional origin of the request, recorded in the audit trail
 */
public record RegisterUserCommand(String email, String rawPassword, String name, String lastName,
                                  String profileImage, String ipAddress) {
}