package com.energymonitor.security.adapter.in.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.energymonitor.security.application.port.in.CreatePasswordResetToken;
import com.energymonitor.security.application.port.in.ResetPassword;
import com.energymonitor.security.application.port.out.ResetAttemptLimiterPort;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * The per-caller limit is charged before the database is touched.
 *
 * <p>Both recovery endpoints open a transaction, and a transaction holds a connection from its first
 * statement. Charging the limit inside the use case would therefore be too late: a caller being
 * refused would already have consumed a connection on its way to being refused, which is exactly
 * what the limit is supposed to avoid. The limiter keeps its counters in memory, so charged from
 * the web adapter it answers without reaching the database at all.
 *
 * <p>The tests below pin the ordering rather than the timing. What they assert is that when the
 * limiter refuses, the use case is never called — and since the use case is what opens the
 * transaction, never called means no connection was taken.
 */
@SpringBootTest
@org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
@Import(ResetAttemptLimiterBeforeDatabaseTest.RefusingLimiter.class)
class ResetAttemptLimiterBeforeDatabaseTest {

    /** Charged on every request in this class, so the limiter always refuses. */
    static final AtomicInteger CHARGED = new AtomicInteger();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ResetAttemptLimiterPort limiter;

    @MockitoBean
    private CreatePasswordResetToken createPasswordResetToken;

    @MockitoBean
    private ResetPassword resetPassword;

    @TestConfiguration
    static class RefusingLimiter {

        @Bean
        @Primary
        ResetAttemptLimiterPort refusingLimiter() {
            return clientIp -> {
                CHARGED.incrementAndGet();
                throw new com.energymonitor.security.application.exception
                        .TooManyResetAttemptsException("too many attempts");
            };
        }
    }

    @Test
    @DisplayName("a refused redemption never reaches the use case, so no transaction is opened")
    void refusedRedemptionStopsBeforeTheUseCase() throws Exception {
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/v1/auth/password/reset")
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"ada@example.com","resetToken":"123456","newPassword":"NewStrong1!"}
                                """))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .status().isTooManyRequests());

        // The whole point: the use case is what opens the transaction.
        verify(resetPassword, never()).reset(any());
        verify(createPasswordResetToken, never()).create(any());
    }

    @Test
    @DisplayName("a refused recovery request never reaches the use case either")
    void refusedRecoveryStopsBeforeTheUseCase() throws Exception {
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/v1/auth/password/forgot")
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"ada@example.com"}
                                """))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .status().isTooManyRequests());

        verify(createPasswordResetToken, never()).create(any());
    }

    @Test
    @DisplayName("the refusal carries Retry-After and says nothing about the account")
    void refusalIsIdenticalWhicheverAccountIsNamed() throws Exception {
        var known = mockMvc.perform(org.springframework.test.web.servlet.request
                        .MockMvcRequestBuilders.post("/api/v1/auth/password/forgot")
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"ada@example.com"}
                                """))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .status().isTooManyRequests())
                .andReturn().getResponse();

        var unknown = mockMvc.perform(org.springframework.test.web.servlet.request
                        .MockMvcRequestBuilders.post("/api/v1/auth/password/forgot")
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"nadie@example.com"}
                                """))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .status().isTooManyRequests())
                .andReturn().getResponse();

        assertThat(unknown.getStatus()).isEqualTo(429);
        assertThat(unknown.getHeader("Retry-After")).isEqualTo("900");

        // Identical except for the instant the error was rendered, which every response carries.
        // A caller cannot tell which addresses are registered from the refusal itself.
        assertThat(unknown.getContentAsString().replaceAll("\"timestamp\":\"[^\"]+\"", ""))
                .isEqualTo(known.getContentAsString().replaceAll("\"timestamp\":\"[^\"]+\"", ""));
    }
}