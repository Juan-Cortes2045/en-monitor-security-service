package com.energymonitor.security.adapter.out.messaging;

import com.energymonitor.security.adapter.out.messaging.SecurityMessagePayloads.EmailVerificationPayload;
import com.energymonitor.security.adapter.out.messaging.SecurityMessagePayloads.PasswordResetPayload;
import com.energymonitor.security.api.EmailVerificationDeliveryPort;
import com.energymonitor.security.api.PasswordResetDeliveryPort;
import java.time.Clock;
import java.time.Instant;
import org.springframework.stereotype.Component;

/**
 * Hands verification and recovery codes to the mail channel of energy-monitor-backend, through
 * the outbox and the message broker.
 *
 * <p>The message expires with the code: once {@code validUntil} has passed it is discarded
 * instead of mailed, both by the relay and, through the message expiration, by the broker.
 */
@Component
public class OutboxMailDeliveryAdapter implements PasswordResetDeliveryPort,
        EmailVerificationDeliveryPort {

    private final OutboxWriter outbox;
    private final Clock clock;

    public OutboxMailDeliveryAdapter(OutboxWriter outbox, Clock clock) {
        this.outbox = outbox;
        this.clock = clock;
    }

    @Override
    public void deliver(String userId, String recipient, String idResetToken, String clearToken,
                        Instant validUntil) {
        outbox.write(SecurityMessageTypes.MAIL_PASSWORD_RESET,
                new PasswordResetPayload(userId, recipient, idResetToken, clearToken, validUntil),
                clock.instant(), validUntil);
    }

    @Override
    public void deliver(String userId, String recipient, String clearCode, Instant validUntil) {
        outbox.write(SecurityMessageTypes.MAIL_EMAIL_VERIFICATION,
                new EmailVerificationPayload(userId, recipient, clearCode, validUntil),
                clock.instant(), validUntil);
    }
}
