package com.energymonitor.security.adapter.out.security;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

/**
 * The checks that need no network: a token is only verified when a client is configured, and
 * anything that is not a JWT is refused before Google's keys are fetched.
 */
class GoogleOAuthClientAdapterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void verifiesNothingWithoutAClient() {
        var adapter = new GoogleOAuthClientAdapter("", "", objectMapper);

        assertTrue(adapter.verify("eyJ.anything.at-all").isEmpty());
    }

    @Test
    void refusesAMissingOrMalformedIdToken() {
        var adapter = new GoogleOAuthClientAdapter("client.apps.googleusercontent.com", "secret",
                objectMapper);

        assertTrue(adapter.verify(null).isEmpty());
        assertTrue(adapter.verify("  ").isEmpty());
        assertTrue(adapter.verify("not-a-jwt").isEmpty());
    }
}
