package com.energymonitor.security.application.port.out;

/**
 * Whether the domain of an email address can receive mail at all.
 *
 * <p>It catches the addresses that cannot be real - an invented or mistyped domain such as
 * {@code gmial.con} - before an account is created for them. It cannot prove that a mailbox
 * exists: that is what the verification code is for.
 */
public interface EmailDomainCheckPort {

    /**
     * @param domain the part of the address after {@code @}
     * @return {@code false} only when the domain certainly cannot receive mail (it does not exist,
     *         or it publishes neither a mail server nor an address); {@code true} otherwise,
     *         including when the answer cannot be obtained, so an outage never blocks registration
     */
    boolean acceptsMail(String domain);
}
