package com.energymonitor.security.api;

import java.time.Instant;

/**
 * Output port for getting a password-reset secret to its owner. This is the extension point
 * the recovery flow waits on, and the only channel through which the secret legitimately
 * leaves the server.
 *
 * <p>The secret exists in the clear in exactly two moments: while it is being generated, and
 * while it is on its way to the person who asked for a reset. Between them it is a hash. That
 * is why the reset endpoint cannot return it and why this port exists instead.
 *
 * <p>An implementation is a client of whatever channel the deployment uses - a mail gateway, an
 * SMS provider, a push service - and it is the only place where the message content and the
 * reset link format are decided. The application layer states what has to be delivered and to
 * whom, and nothing about how.
 *
 * <p>This interface lives in the {@code api} package rather than beside the other output ports
 * because it is the one output port that is not private to this module: an adapter in another
 * module implements it, and Modulith only lets other modules see what {@code api} exposes.
 *
 * <p><strong>The recipient crosses this boundary as a plain address, not as the
 * {@code Email} value object.</strong> An outbound port
 * is a contract offered to code outside this module, and a value object from inside the domain
 * would drag the whole aggregate graph across with it, exposing internals that the channel has
 * no business knowing. The address has already been validated by the time it reaches here, so
 * the domain gains nothing by having its own type carried along.
 *
 * <p><strong>Implementations must not throw a distinguishable error.</strong> The endpoint that
 * triggers delivery answers 202 whether or not the account exists, so an implementation that
 * lets a transport failure escape would turn a delivery outage into a way of learning which
 * addresses are registered. The use case therefore treats a failure here as undeliverable and
 * keeps the acknowledgement neutral.
 */
public interface PasswordResetDeliveryPort {

    /**
     * Delivers a reset secret to the account that requested it.
     *
     * <p>The account identifier and the token identifier are part of the contract rather than an
     * implementation detail: the channel records where a message came from, so it needs to be told
     * which row the message is about. Both are opaque identifiers, not objects from this module's
     * domain.
     *
     * @param userId       the account the recovery belongs to, recorded by the channel
     * @param recipient    the address the recovery belongs to
     * @param idResetToken the token being delivered, recorded by the channel as the message's source
     * @param clearToken   the secret in clear text, valid until {@code validUntil}
     * @param validUntil   the instant the secret stops being redeemable
     */
    void deliver(String userId, String recipient, String idResetToken, String clearToken,
                 Instant validUntil);
}
