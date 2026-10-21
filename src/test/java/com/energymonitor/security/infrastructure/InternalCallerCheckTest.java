package com.energymonitor.security.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

@DisplayName("Internal caller check")
class InternalCallerCheckTest {

    @Test
    @DisplayName("with no token configured nobody is trusted")
    void failsClosedWithoutToken() {
        InternalCallerCheck check = new InternalCallerCheck(properties(""));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Internal-Token", "");

        assertThat(check.trusts(request)).isFalse();
    }

    @Test
    @DisplayName("a caller in the network with the token is trusted")
    void trustsTheBackend() {
        InternalCallerCheck check = new InternalCallerCheck(properties("secret"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("172.18.0.5");
        request.addHeader("X-Internal-Token", "secret");

        assertThat(check.trusts(request)).isTrue();
    }

    private static InternalApiProperties properties(String token) {
        return new InternalApiProperties(token, List.of("127.0.0.1/32", "172.16.0.0/12"),
                URI.create("http://localhost:8080"), Duration.ofSeconds(1), Duration.ofSeconds(2));
    }
}
