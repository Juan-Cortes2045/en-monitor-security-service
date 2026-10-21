package com.energymonitor.security.adapter.out.messaging;

import java.util.Set;

/**
 * The messages this service publishes, named by their routing key on the
 * {@code energy-monitor.security} topic exchange.
 *
 * <p>These names are a contract with the services that consume them: renaming one silently
 * stops its delivery, because the consumer's binding no longer matches.
 */
public final class SecurityMessageTypes {

    /** A new account, by registration or by a first Google sign-in. */
    public static final String ACCOUNT_REGISTERED = "account.registered";

    /** An administrator changed an account's status or global roles. */
    public static final String ACCOUNT_ADMINISTERED = "account.administered";

    /** An account was deleted: its memberships and the homes it alone owned must go. */
    public static final String ACCOUNT_DELETED = "account.deleted";

    /** A verification code to mail. Carries the code in clear text. */
    public static final String MAIL_EMAIL_VERIFICATION = "mail.email-verification";

    /** A password recovery code to mail. Carries the code in clear text. */
    public static final String MAIL_PASSWORD_RESET = "mail.password-reset";

    /** The types whose payload holds a secret and is wiped once the broker confirms it. */
    public static final Set<String> CARRY_SECRETS = Set.of(MAIL_EMAIL_VERIFICATION, MAIL_PASSWORD_RESET);

    private SecurityMessageTypes() {
    }
}
