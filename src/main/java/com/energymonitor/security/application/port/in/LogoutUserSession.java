package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.LogoutUserSessionCommand;

/**
 * Input port for logging out of an authenticated session.
 *
 * <p>Logout is the ordinary end of a session, not a security decision about it. The domain
 * keeps that distinction against {@code revoke}, which invalidates a credential because it may
 * be in someone else's hands, and this port deliberately exposes only the ordinary path.
 */
public interface LogoutUserSession {

    /**
     * Closes the session named by the command.
     *
     * @param command the session to close
     */
    void logout(LogoutUserSessionCommand command);
}
