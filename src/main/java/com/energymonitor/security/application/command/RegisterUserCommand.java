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
 * @param acceptTerms  whether the person accepted the terms and conditions; required
 */
public record RegisterUserCommand(String email, String rawPassword, String name, String lastName,
                                  String profileImage, String ipAddress, boolean acceptTerms) {

    /** A registration whose terms were accepted. */
    public RegisterUserCommand(String email, String rawPassword, String name, String lastName,
                               String profileImage, String ipAddress) {
        this(email, rawPassword, name, lastName, profileImage, ipAddress, true);
    }
}