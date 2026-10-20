package com.energymonitor.security.adapter.in.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.energymonitor.security.infrastructure.JwtKeyedTest;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * The per-address limit is charged without a connection, proven by having none to give.
 *
 * <p>The ordering claim behind the limit is a claim about the database: a caller whose window is
 * spent must be refused without the request ever waiting on a connection, or a pool that is already
 * busy turns a rejected request into a slow one. Asserting that no use case runs proves less than
 * it looks like, because a mock is consulted whether or not a pool is in the way. So the pool here
 * is cut to a single connection and held for the length of the test, and the assertion is that a
 * spent address still gets its answer on time.
 *
 * <p>{@code connection-timeout} is 250 ms and the ceiling asserted is 200 ms. That gap is the
 * actual assertion: a request that reached the pool could not have come back in under 200 ms, it
 * would have failed waiting for one. The window is {@code max-attempts-per-window}, ten, so the
 * eleventh request from an address is the refused one.
 */
@DisplayName("El limite por IP se aplica sin esperar una conexion del pool")
@SpringBootTest
@org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
class PoolSaturatedLimiterTest extends JwtKeyedTest {

    /** A caller waiting this long for a connection has already waited too long. */
    private static final long CEILING_MS = 200;

    /** Deliberately larger than {@link #CEILING_MS}: it is the signal, not the limit. */
    private static final int CONNECTION_TIMEOUT_MS = 250;

    private static final int ALLOWED_PER_WINDOW = 10;

    private static final String UNKNOWN_ACCOUNT = "{\"email\":\"nadie-aqui@example.com\"}";

    @DynamicPropertySource
    static void starveThePool(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.hikari.maximum-pool-size", () -> 1);
        registry.add("spring.datasource.hikari.minimum-idle", () -> 1);
        registry.add("spring.datasource.hikari.connection-timeout", () -> CONNECTION_TIMEOUT_MS);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private DataSource dataSource;

    @Test
    @DisplayName("una direccion con la ventana agotada recibe 429 sin acquire")
    void refusesASpentAddressWithoutAConnection() throws Exception {
        Connection held = dataSource.getConnection();
        try {
            assertThat(poolIsExhausted()).isTrue();

            for (int attempt = 1; attempt <= ALLOWED_PER_WINDOW; attempt++) {
                Call accepted = forgot("198.51.100.10");
                assertThat(accepted.status()).isEqualTo(202);
                assertThat(accepted.elapsedMs())
                        .as("even an accepted request answers on the queue, not on the database")
                        .isLessThan(CEILING_MS);
            }

            Call refused = forgot("198.51.100.10");

            assertThat(refused.status()).isEqualTo(429);
            assertThat(refused.elapsedMs())
                    .as("a refused request must not have waited for the pool")
                    .isLessThan(CEILING_MS);
        } finally {
            held.close();
        }
    }

    @Test
    @DisplayName("otra direccion sigue atendida mientras la primera se rechaza")
    void servesAnotherAddressWhileTheFirstIsRefused() throws Exception {
        Connection held = dataSource.getConnection();
        try {
            for (int attempt = 1; attempt <= ALLOWED_PER_WINDOW; attempt++) {
                assertThat(forgot("198.51.100.20").status()).isEqualTo(202);
            }
            assertThat(forgot("198.51.100.20").status()).isEqualTo(429);

            assertThat(forgot("198.51.100.21").status())
                    .as("the window belongs to the address, not to the endpoint")
                    .isEqualTo(202);
        } finally {
            held.close();
        }
    }

    /**
     * Confirms the pool really has nothing left to hand out.
     *
     * <p>The assertion is both halves of it: a second acquire fails, and it took at least the
     * configured timeout doing so, which is what waiting for a connection looks like from here.
     */
    private boolean poolIsExhausted() {
        long start = System.nanoTime();
        assertThatThrownBy(dataSource::getConnection)
                .as("the only connection is already held, so a second acquire cannot succeed")
                .isInstanceOf(SQLException.class);
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) >= CONNECTION_TIMEOUT_MS;
    }

    private Call forgot(String remoteAddr) throws Exception {
        long start = System.nanoTime();
        int status = mockMvc.perform(post("/api/v1/auth/password/forgot")
                        .with(request -> {
                            request.setRemoteAddr(remoteAddr);
                            return request;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(UNKNOWN_ACCOUNT))
                .andReturn()
                .getResponse()
                .getStatus();
        return new Call(status, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start));
    }

    private record Call(int status, long elapsedMs) {}
}