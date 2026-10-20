package com.energymonitor.security.application.port.in;

/**
 * Input port for confirming that an account owns its email address.
 */
public interface EmailVerification {

    /**
     * Sends the current verification code to the account registered under {@code email}.
     *
     * <p>Does nothing, without saying so, when no active account uses the address or it is
     * already verified: the caller must not be able to tell those cases apart.
     *
     * @param email the address to verify
     */
    void sendCode(String email);

    /**
     * Marks the account's email as verified when {@code code} is the one that was sent.
     *
     * @param email the address being verified
     * @param code  the six-digit code from the email
     * @throws com.energymonitor.security.application.exception.InvalidVerificationCodeException
     *         when the account does not exist or the code is wrong or expired, indistinguishably
     */
    void verify(String email, String code);
}
