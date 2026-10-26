package com.energymonitor.security.application.port.out;

import com.energymonitor.security.application.result.GoogleIdentity;
import java.util.Optional;

/**
 * Turns what a client got from Google (the web popup's authorization code, or the mobile app's
 * ID token) into a verified identity.
 */
public interface GoogleIdentityPort {

    /** Whether a Google client is configured; without it Google sign-in is unavailable. */
    boolean isConfigured();

    /**
     * @return the identity of a valid code whose ID token is signed by Google for this client;
     *         empty for an invalid, expired or reused code
     */
    Optional<GoogleIdentity> exchange(String authorizationCode);

    /**
     * @return the identity of an ID token signed by Google, issued by Google and addressed to
     *         this client; empty for a forged, expired or foreign token
     */
    Optional<GoogleIdentity> verify(String idToken);
}
