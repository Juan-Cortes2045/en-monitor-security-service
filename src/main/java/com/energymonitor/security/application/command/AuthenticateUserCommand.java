package com.energymonitor.security.application.command;

/**
 * Input of {@code AuthenticateUser}: the credentials of a login attempt.
 *
 * @param email       account address
 * @param rawPassword plain-text password, matched against the stored hash by the hasher port
 * @param ipAddress   optional origin of the attempt, recorded in the audit trail
 */
public record AuthenticateUserCommand(String email, String rawPassword, String ipAddress) {
}