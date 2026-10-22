package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.AuthenticateUserCommand;
import com.energymonitor.security.application.result.AuthenticationResult;

/**
 * Input port for authenticating an account with credentials.
 */
public interface AuthenticateUser {

    /**
     * @param command the credentials and origin of the attempt
     * @return the outcome; never throws for wrong credentials
     */
    AuthenticationResult authenticate(AuthenticateUserCommand command);
}