package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.ChangePasswordCommand;

/**
 * Input port for changing the password of an authenticated account.
 */
public interface ChangePassword {

    /**
     * @param command the current and new password
     */
    void change(ChangePasswordCommand command);
}