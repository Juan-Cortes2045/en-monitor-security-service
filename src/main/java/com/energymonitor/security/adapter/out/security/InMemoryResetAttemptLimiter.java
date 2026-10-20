package com.energymonitor.security.adapter.out.security;

import com.energymonitor.security.application.exception.TooManyResetAttemptsException;
import com.energymonitor.security.application.port.out.ResetAttemptLimiterPort;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory allowance of password-recovery attempts per caller address.
 *
 * <h2>What this buys and what it costs</h2>
 *
 * <p>It is the control that lets a six-digit code exist. Without a bound on attempts, a million
 * candidates is a few hours of requests; with ten per fifteen minutes, exhausting the space would
 * take years.
 *
 * <p>Its limits are real and are stated here rather than discovered later:
 *
 * <ul>
 *   <li><strong>It is per instance.</strong> Two replicas each allow the full allowance, so the
 *       effective limit scales with the number of instances. Behind a shared limiter, or a load
 *       balancer that counts, this would be exact.</li>
 *   <li><strong>It is not durable.</strong> A restart clears the allowance. That is the safe
 *       direction to fail: the cost is a fresh allowance, not a locked-out account.</li>
 *   <li><strong>It cannot expire entries on a timer</strong> without holding a thread, so entries
 *       are dropped when they are next encountered and the whole map is swept when it grows past
 *       {@link #MAX_ENTRIES}.</li>
 * </ul>
 *
 * <p>None of that makes it a substitute for a rate limiter in front of the service. It is the
 * part that has to live inside the application anyway, because the endpoint has to answer 429
 * rather than 400 for a caller that is going too fast.
 *
 * <h2>Why a fixed window rather than a sliding one</h2>
 *
 * <p>A window that slid on every attempt would let a caller spread the allowance thinly across
 * hours. A fixed window can be gamed at the boundary by spending the allowance just before it
 * ends, which allows twice the intended rate in the worst case. The common alternative of
 * storing every attempt timestamp is exact but grows without bound under attack, which is the
 * wrong property for the one component whose job is to withstand that. A fixed window is chosen
 * because the bound it gives is the one that matters, and its worst case is twice the limit
 * rather than unlimited.
 */
public class InMemoryResetAttemptLimiter implements ResetAttemptLimiterPort {

    /**
     * Above this many addresses, expired entries are swept. Bounds memory against an attacker who
     * rotates source addresses, at the cost of one pass over the map on an uncommon path.
     */
    private static final int MAX_ENTRIES = 10_000;

    private static final String UNKNOWN_CALLER = "unknown";

    private final int maxAttempts;
    private final Duration windowDuration;
    private final Clock clock;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    /**
     * @param maxAttempts how many attempts one address may make per window, at least 1
     * @param window      how long that allowance lasts, positive
     * @param clock       the time source, so a test can move past a window
     * @throws IllegalArgumentException if either bound is not usable
     */
    public InMemoryResetAttemptLimiter(int maxAttempts, Duration window, Clock clock) {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be at least 1, got " + maxAttempts);
        }
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be a positive duration, got " + window);
        }
        this.maxAttempts = maxAttempts;
        this.windowDuration = window;
        this.clock = clock;
    }

    @Override
    public void checkAllowed(String clientIp) {
        String key = clientIp == null || clientIp.isBlank() ? UNKNOWN_CALLER : clientIp;
        if (windows.size() > MAX_ENTRIES) {
            sweep();
        }
        Instant reference = clock.instant();
        // Returned rather than thrown from inside compute: a mapping function that threw would
        // leave the entry unwritten, so the next caller would be counted from a stale total.
        Window window = windows.compute(key,
                (ignored, existing) -> existing == null
                        ? Window.starting(reference)
                        : existing.recorded(reference, windowDuration));
        if (window.attempts() > maxAttempts) {
            throw new TooManyResetAttemptsException(
                    "too many password recovery attempts; try again later");
        }
    }

    /**
     * Drops the windows that have run out.
     *
     * <p>Iterating weakly consistent, which is what {@link ConcurrentHashMap} offers, is correct
     * here: an entry removed while another thread is inside {@code compute} for it is either
     * re-inserted by that thread or lost, and losing it costs at most one fresh allowance.
     */
    private void sweep() {
        Instant reference = clock.instant();
        Iterator<Map.Entry<String, Window>> entries = windows.entrySet().iterator();
        while (entries.hasNext()) {
            if (entries.next().getValue().hasElapsed(reference, windowDuration)) {
                entries.remove();
            }
        }
    }

    /**
     * One address's allowance and the instant its window began.
     *
     * <p>Immutable and replaced rather than mutated, so two concurrent requests for the same
     * address cannot both read a count and both write it back, which would silently undercount and
     * hand out more attempts than configured.
     *
     * @param windowStarted when the current window began
     * @param attempts      how many attempts this window has recorded
     */
    private record Window(Instant windowStarted, int attempts) {

        static Window starting(Instant now) {
            return new Window(now, 1);
        }

        /**
         * Counts this attempt, opening a new window when the previous one has run out.
         *
         * @param now      the current instant
         * @param duration length of the window
         * @return the window as it stands after this attempt
         */
        Window recorded(Instant now, Duration duration) {
            return hasElapsed(now, duration)
                    ? new Window(now, 1)
                    : new Window(windowStarted, attempts + 1);
        }

        /**
         * @param now      the current instant
         * @param duration length of the window
         * @return whether this window has run out
         */
        boolean hasElapsed(Instant now, Duration duration) {
            return !now.isBefore(windowStarted.plus(duration));
        }
    }
}
