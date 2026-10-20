package com.energymonitor.security.adapter.out.mail;

import com.energymonitor.security.api.EmailVerificationDeliveryPort;
import com.energymonitor.security.api.PasswordResetDeliveryPort;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Stand-in for the mail channel while this service has no route to it.
 *
 * <p>Mail is sent by the notification module of energy-monitor-backend. Inside the monolith it
 * implemented these two ports directly; once separated, the requests travel over the message
 * broker, which arrives in the next step of the migration. Until then a request is only logged,
 * and the code itself never is: a recovery or verification code in a log file is a credential.
 */
@Component
public class UnroutedMailDeliveryAdapter implements PasswordResetDeliveryPort,
        EmailVerificationDeliveryPort {

    private static final Logger LOG = LoggerFactory.getLogger(UnroutedMailDeliveryAdapter.class);

    @Override
    public void deliver(String userId, String recipient, String idResetToken, String clearToken,
                        Instant validUntil) {
        LOG.warn("Password reset {} for account {} not sent: no mail channel is connected",
                idResetToken, userId);
    }

    @Override
    public void deliver(String userId, String recipient, String clearCode, Instant validUntil) {
        LOG.warn("Email verification for account {} not sent: no mail channel is connected",
                userId);
    }
}
