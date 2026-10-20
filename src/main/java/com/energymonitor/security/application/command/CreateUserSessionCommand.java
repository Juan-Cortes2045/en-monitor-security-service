package com.energymonitor.security.application.command;

/**
 * Input of {@code CreateUserSession}: opens a new authenticated session for an account.
 *
 * @param idUser    the account
 * @param ipAddress optional client IP
 * @param userAgent optional client agent
 */
public record CreateUserSessionCommand(String idUser, String ipAddress, String userAgent) {
}