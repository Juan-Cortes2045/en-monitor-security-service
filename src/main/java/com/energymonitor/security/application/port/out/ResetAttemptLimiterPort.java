package com.energymonitor.security.application.port.out;

import com.energymonitor.security.application.exception.TooManyResetAttemptsException;

/**
 * Output port for bounding how often one caller may attempt to redeem a password-recovery code.
 *
 * <p>This is the control that makes a six-digit code defensible. A million combinations is few
 * enough to exhaust over the network, so the answer is not a longer code but a slower network.
 *
 * <p>It is deliberately keyed by caller address and not by account: the reset request does not
 * carry the email, so an attempt cannot be attributed to an account, and a limiter that needed
 * one could not be consulted at all. The allowance is therefore shared by everything behind one
 * address, which is a real cost for users behind a corporate NAT and the reason the limit is
 * generous enough to absorb them.
 *
 * <p>Every attempt counts, whether the code presented was right or wrong. A limiter that only
 * charged for failures would leak, through its own timing, how close a guess had come.
 */
public interface ResetAttemptLimiterPort {

    /**
     * Records one redemption attempt and refuses the caller when the allowance is spent.
     *
     * @param clientIp the address the request came from
     * @throws TooManyResetAttemptsException if this address has used its allowance for the window
     */
    void checkAllowed(String clientIp);
}
