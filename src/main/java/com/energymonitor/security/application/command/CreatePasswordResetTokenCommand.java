package com.energymonitor.security.application.command;

/**
 * Input of {@code CreatePasswordResetToken}: the account to recover.
 *
 * @param email the account address
 */
public record CreatePasswordResetTokenCommand(String email) {
}