package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.CreateUserSessionCommand;
import com.energymonitor.security.domain.model.UserSession;

/**
 * Input port for opening a new authenticated session.
 */
public interface CreateUserSession {

    /**
     * @param command the account and client context
     * @return the opened session
     */
    UserSession create(CreateUserSessionCommand command);
}