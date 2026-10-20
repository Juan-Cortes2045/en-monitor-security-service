package com.energymonitor.security.application.port.out;

import com.energymonitor.security.application.result.GoogleIdentity;
import java.util.Optional;

/**
 * Exchanges the authorization code the browser got from Google for a verified identity.
 */
public interface GoogleIdentityPort {

    /** Whether a Google client is configured; without it Google sign-in is unavailable. */
    boolean isConfigured();

    /**
     * @return the identity of a valid code whose ID token is signed by Google for this client;
     *         empty for an invalid, expired or reused code
     */
    Optional<GoogleIdentity> exchange(String authorizationCode);
}
