package com.energymonitor.security.api;

import java.time.Instant;

/**
 * Output port for getting an email-verification code to the address it confirms.
 *
 * <p>Lives in {@code api} for the same reason as {@link PasswordResetDeliveryPort}: an adapter in
 * another module implements it. The recipient crosses the boundary as a plain address, and an
 * implementation must not let a transport failure escape, so a mail outage cannot turn into a
 * failed registration.
 */
public interface EmailVerificationDeliveryPort {

    /**
     * Delivers a verification code.
     *
     * @param userId     the account being verified, recorded by the channel
     * @param recipient  the address the code confirms
     * @param clearCode  the six-digit code
     * @param validUntil the latest instant the code is still accepted
     */
    void deliver(String userId, String recipient, String clearCode, Instant validUntil);
}
