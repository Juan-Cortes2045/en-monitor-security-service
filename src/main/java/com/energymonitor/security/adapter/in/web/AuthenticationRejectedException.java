package com.energymonitor.security.adapter.in.web;

/**
 * Signals that an authentication attempt was refused, without saying why.
 *
 * <p>This is a delivery-layer concern rather than an application one. The application layer
 * reports the precise reason in typed statuses and error records; how much of that reaches the
 * caller is a policy decision, and for a login attempt the answer is none. An unknown address,
 * a wrong password, a blocked account and a missing account therefore all surface as the same
 * 401 with the same message, and an attacker learns nothing about which addresses exist.
 *
 * <p>It exists as an exception so the response is rendered by the same handler that renders
 * every other failure, which keeps one error shape across the API.
 */
public class AuthenticationRejectedException extends RuntimeException {

    private static final String GENERIC_MESSAGE = "Invalid credentials.";

    public AuthenticationRejectedException() {
        super(GENERIC_MESSAGE);
    }
}
