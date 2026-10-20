package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.CreatePasswordResetTokenCommand;
import com.energymonitor.security.domain.model.PasswordResetToken;

/**
 * Input port for issuing a password-recovery token.
 */
public interface CreatePasswordResetToken {

    /**
     * Issues a token and hands its clear secret to the delivery channel.
     *
     * <p>The returned token still carries that secret in memory, because the delivery adapter
     * may need it after the use case returns. It is transient: nothing persists it, and a caller
     * that builds a response out of this object must not serialise it into one. The delivery
     * channel, not the API response, is where a reset token belongs.
     *
     * @param command the account to recover
     * @return the issued token, whose value was delivered out of band
     */
    PasswordResetToken create(CreatePasswordResetTokenCommand command);
}
