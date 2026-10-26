package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.RegisterUserCommand;
import com.energymonitor.security.domain.model.PendingRegistration;

/**
 * Input port for asking for a new account. The account itself is created by
 * {@link EmailVerification#verify} once the address is confirmed.
 */
public interface RegisterUser {

    /**
     * @param command the registration data
     * @return the request waiting for its verification code
     */
    PendingRegistration register(RegisterUserCommand command);
}
