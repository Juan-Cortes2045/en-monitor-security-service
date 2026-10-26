package com.energymonitor.security.application.command;

/**
 * Input of {@code AuthenticateUser}: the credentials of a login attempt.
 *
 * @param email       account address
 * @param rawPassword plain-text password, matched against the stored hash by the hasher port
 * @param ipAddress   optional origin of the attempt, recorded in the audit trail
 * @param acceptTerms whether the person accepts the terms now, for an account that never did
 */
public record AuthenticateUserCommand(String email, String rawPassword, String ipAddress,
                                      boolean acceptTerms) {

    /** An attempt that accepts nothing new. */
    public AuthenticateUserCommand(String email, String rawPassword, String ipAddress) {
        this(email, rawPassword, ipAddress, false);
    }
}