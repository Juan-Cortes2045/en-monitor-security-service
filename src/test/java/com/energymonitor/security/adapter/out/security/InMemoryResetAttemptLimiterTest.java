package com.energymonitor.security.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.energymonitor.security.application.exception.TooManyResetAttemptsException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("Password-recovery attempt limiter")
class InMemoryResetAttemptLimiterTest {

    private static final int MAX_ATTEMPTS = 3;
    private static final Duration WINDOW = Duration.ofMinutes(15);
    private static final Instant START = Instant.parse("2026-01-02T03:04:05Z");

    private final MutableClock clock = new MutableClock(START);

    private InMemoryResetAttemptLimiter limiter() {
        return new InMemoryResetAttemptLimiter(MAX_ATTEMPTS, WINDOW, clock);
    }

    /** A clock a test can move, so a window can be made to pass without waiting for it. */
    private static final class MutableClock extends Clock {

        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration amount) {
            now = now.plus(amount);
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    @Nested
    @DisplayName("while the allowance lasts")
    class WithinAllowance {

        @Test
        @DisplayName("admits exactly the configured number of attempts")
        void admitsTheConfiguredNumber() {
            InMemoryResetAttemptLimiter limiter = limiter();

            for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
                assertThatCode(() -> limiter.checkAllowed("203.0.113.7"))
                        .doesNotThrowAnyException();
            }
        }

        @Test
        @DisplayName("refuses the attempt after that, which is the control a six-digit code needs")
        void refusesTheAttemptPastIt() {
            InMemoryResetAttemptLimiter limiter = limiter();
            for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
                limiter.checkAllowed("203.0.113.7");
            }

            assertThatThrownBy(() -> limiter.checkAllowed("203.0.113.7"))
                    .isInstanceOf(TooManyResetAttemptsException.class);
        }

        @Test
        @DisplayName("counts every address separately")
        void countsAddressesSeparately() {
            InMemoryResetAttemptLimiter limiter = limiter();
            for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
                limiter.checkAllowed("203.0.113.7");
            }

            assertThatCode(() -> limiter.checkAllowed("198.51.100.9"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("treats a missing address as one caller, not as unlimited")
        void countsAMissingAddressAsOneCaller() {
            InMemoryResetAttemptLimiter limiter = limiter();
            for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
                limiter.checkAllowed(null);
            }

            assertThatThrownBy(() -> limiter.checkAllowed("   "))
                    .isInstanceOf(TooManyResetAttemptsException.class);
        }
    }

    @Nested
    @DisplayName("once the window has passed")
    class AfterTheWindow {

        @Test
        @DisplayName("opens a fresh allowance")
        void reopensTheAllowance() {
            InMemoryResetAttemptLimiter limiter = limiter();
            for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
                limiter.checkAllowed("203.0.113.7");
            }
            assertThatThrownBy(() -> limiter.checkAllowed("203.0.113.7"))
                    .isInstanceOf(TooManyResetAttemptsException.class);

            clock.advance(WINDOW.plusSeconds(1));

            assertThatCode(() -> limiter.checkAllowed("203.0.113.7"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("does not reopen one instant early")
        void doesNotReopenEarly() {
            InMemoryResetAttemptLimiter limiter = limiter();
            for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
                limiter.checkAllowed("203.0.113.7");
            }

            clock.advance(WINDOW.minusSeconds(1));

            assertThatThrownBy(() -> limiter.checkAllowed("203.0.113.7"))
                    .isInstanceOf(TooManyResetAttemptsException.class);
        }
    }

    @Nested
    @DisplayName("when configured")
    class Configuration {

        @Test
        @DisplayName("refuses an allowance of zero, which would lock every caller out")
        void refusesAZeroAllowance() {
            assertThatThrownBy(() -> new InMemoryResetAttemptLimiter(0, WINDOW, clock))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("refuses a window that is not a positive duration")
        void refusesAnUnusableWindow() {
            assertThatThrownBy(() -> new InMemoryResetAttemptLimiter(1, Duration.ZERO, clock))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> new InMemoryResetAttemptLimiter(1, Duration.ofMinutes(-1), clock))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> new InMemoryResetAttemptLimiter(1, null, clock))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
