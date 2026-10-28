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

    /** An account signed in for the first time, its address verified: its owner is welcomed. */
    public static final String ACCOUNT_FIRST_SIGNED_IN = "account.first-signed-in";

    /** A verification code to mail. Carries the code in clear text. */
    public static final String MAIL_EMAIL_VERIFICATION = "mail.email-verification";

    /** A password recovery code to mail. Carries the code in clear text. */
    public static final String MAIL_PASSWORD_RESET = "mail.password-reset";

    /**
     * The code that confirms the deletion of an account created with Google. Carries the code in
     * clear text. The notification service does not consume it yet: it is only published once
     * {@code security.account-deletion.code-mail-enabled} is turned on.
     */
    public static final String MAIL_ACCOUNT_DELETION = "mail.account-deletion";

    /** The types whose payload holds a secret and is wiped once the broker confirms it. */
    public static final Set<String> CARRY_SECRETS = Set.of(MAIL_EMAIL_VERIFICATION, MAIL_PASSWORD_RESET,
            MAIL_ACCOUNT_DELETION);

    private SecurityMessageTypes() {
    }
}
