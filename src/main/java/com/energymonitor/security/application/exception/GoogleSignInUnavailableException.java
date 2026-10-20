package com.energymonitor.security.application.exception;

/**
 * Google sign-in is not configured on this server ({@code GOOGLE_CLIENT_ID}).
 */
public class GoogleSignInUnavailableException extends SecurityApplicationException {

    public GoogleSignInUnavailableException(String message) {
        super(message);
    }
}
