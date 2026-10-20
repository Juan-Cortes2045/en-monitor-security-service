package com.energymonitor.security.infrastructure;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Common configuration for any test that boots the whole application.
 *
 * <p>{@code security.jwt.private-key-path} and {@code security.jwt.public-key-path} have no
 * sensible default: an empty value is a deployment mistake the application is meant to refuse.
 * A {@code @SpringBootTest} that inherited those empty values would therefore fail on the
 * signing bean rather than on what it is actually testing, so the paths are supplied here from a
 * key pair generated for the test run, together with the issuer and the token lifetime the
 * assertions expect.
 *
 * <p>Extending this class is enough: Spring Test picks up the inherited {@code @DynamicPropertySource}
 * method, so no test has to repeat it, and no key is ever written into the repository.
 */
public abstract class JwtKeyedTest {

    private static final JwtTestKeys.Keys KEYS = JwtTestKeys.generate();

    @DynamicPropertySource
    static void jwtKeys(DynamicPropertyRegistry registry) {
        registry.add("security.jwt.private-key-path", () -> KEYS.privateKey().toString());
        registry.add("security.jwt.public-key-path", () -> KEYS.publicKey().toString());
        registry.add("security.jwt.issuer", () -> JwtTestKeys.ISSUER);
        registry.add("security.jwt.access-token-ttl", () -> JwtTestKeys.ACCESS_TOKEN_TTL);
    }

    /**
     * The key pair the application is signing with in this test.
     *
     * @return the generated pair, for a test that verifies a token on its own
     */
    protected static JwtTestKeys.Keys keys() {
        return KEYS;
    }
}
