package com.energymonitor.security.application.result;

/**
 * How a refresh attempt ended.
 *
 * <p>The three outcomes are deliberately distinct rather than a success flag with a message.
 * A replay is not a bad request, it is a security event, and collapsing it into a generic
 * failure would let a caller keep retrying without ever learning that the family was
 * invalidated.
 */
public enum RefreshStatus {

    /**
     * The token was active and valid. A replacement generation has been issued and the
     * presented one retired.
     */
    ROTATED,

    /**
     * The token is unknown, expired, revoked, or its session is gone. Nothing was changed.
     */
    REJECTED,

    /**
     * The token had already been exchanged. The whole family has been revoked and the session
     * marked as compromised, and no new credential was issued.
     */
    REUSE_DETECTED
}
