package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.RegisterUserCommand;
import com.energymonitor.security.domain.model.User;

/**
 * Input port for creating a new {@code Person} and its {@code User} account.
 */
public interface RegisterUser {

    /**
     * @param command the registration data
     * @return the registered user
     */
    User register(RegisterUserCommand command);
}