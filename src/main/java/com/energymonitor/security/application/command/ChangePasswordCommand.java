package com.energymonitor.security.application.command;

/**
 * Input of {@code ChangePassword}: the authenticated user replaces their password.
 *
 * @param idUser          the account
 * @param currentPassword the password currently in force, verified by the hasher port
 * @param newPassword     the new plain-text password, validated against the policy
 * @param ipAddress       optional origin of the request, recorded in the audit trail
 */
public record ChangePasswordCommand(String idUser, String currentPassword, String newPassword,
                                    String ipAddress) {
}