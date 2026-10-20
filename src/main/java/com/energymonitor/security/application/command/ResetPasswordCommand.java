package com.energymonitor.security.application.command;

/**
 * Redeems a recovery code and sets a new password.
 *
 * @param email       the account the code was requested for; the redemption is bound to it
 * @param resetToken  the six-digit code, in clear text
 * @param newPassword the replacement, in clear text
 * @param ipAddress   origin of the request, recorded in the audit trail and charged to the
 *                    per-caller attempt allowance
 */
public record ResetPasswordCommand(String email, String resetToken, String newPassword,
                                   String ipAddress) {
}
