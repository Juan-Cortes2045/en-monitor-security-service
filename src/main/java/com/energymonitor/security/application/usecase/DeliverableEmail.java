package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.exception.UndeliverableEmailException;
import com.energymonitor.security.application.port.out.EmailDomainCheckPort;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.service.MistypedEmailDomains;

/**
 * The checks an address passes before an account takes it, at registration and when the email
 * of a profile changes.
 *
 * <p>The mistyped-provider check runs first: it needs no network, and it catches the domains DNS
 * cannot, because they were registered to collect the mail of a typo. Whether the mailbox itself
 * exists is what the verification code then proves.
 */
final class DeliverableEmail {

    private DeliverableEmail() {
    }

    /** @throws UndeliverableEmailException when the domain is mistyped or cannot receive mail */
    static void require(Email email, EmailDomainCheckPort domains) {
        MistypedEmailDomains.intendedProvider(email.domain()).ifPresent(provider -> {
            throw new UndeliverableEmailException("The domain of the email address looks "
                    + "mistyped: did you mean " + provider + "?");
        });
        if (!domains.acceptsMail(email.domain())) {
            throw new UndeliverableEmailException("The domain of the email address does not exist "
                    + "or cannot receive mail.");
        }
    }
}
