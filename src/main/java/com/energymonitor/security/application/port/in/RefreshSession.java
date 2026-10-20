package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.RefreshSessionCommand;
import com.energymonitor.security.application.result.RefreshSessionResult;

/**
 * Input port for exchanging a refresh token for a new one.
 *
 * <p>Rotation is single use. Every successful call retires the presented generation and issues
 * its successor in the same family, so a secret is good for exactly one exchange. Presenting a
 * retired secret is not a mistake to be reported as such: it is treated as theft, and the whole
 * family is invalidated.
 */
public interface RefreshSession {

    /**
     * Exchanges a refresh token for a replacement.
     *
     * @param command the presented secret and the caller's address
     * @return the outcome, carrying a new secret only when the attempt was legitimate
     */
    RefreshSessionResult refresh(RefreshSessionCommand command);
}
