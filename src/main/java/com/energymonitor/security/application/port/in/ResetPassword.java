package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.ResetPasswordCommand;

/**
 * Input port for redeeming a password-reset token.
 */
public interface ResetPassword {

    /**
     * @param command the token and the new password
     */
    void reset(ResetPasswordCommand command);
}