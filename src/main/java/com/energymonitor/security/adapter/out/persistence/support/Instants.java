package com.energymonitor.security.adapter.out.persistence.support;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Storage-precision helpers for the Security persistence adapter.
 *
 * <p>Every {@code timestamp} column created by the Security changelogs is declared without
 * fractional seconds, so MySQL stores whole seconds. A value carrying nanoseconds would be
 * silently rounded on write and come back different, which breaks two things the domain
 * depends on:
 *
 * <ul>
 *   <li>Round-trip equality: a persisted instant would not compare equal to the original.</li>
 *   <li>The validity-window invariant. {@code PasswordResetToken} and {@code UserSession}
 *       require {@code expirationAt > createdAt}. A window narrower than one second would
 *       collapse to two identical seconds on disk and the domain would then refuse to
 *       rehydrate the row, even though it had just been written as valid.</li>
 * </ul>
 *
 * <p>Truncating on the way out makes the stored value predictable and the round trip
 * lossless. It is a storage concern, so it lives here and never reaches the domain, which
 * keeps full nanosecond precision in memory.
 */
public final class Instants {

    /**
     * Resolution actually persisted by the schema. Matches {@code DATETIME_PRECISION = 0} on
     * every Security {@code timestamp} column.
     */
    public static final ChronoUnit STORAGE_PRECISION = ChronoUnit.SECONDS;

    private Instants() {
    }

    /**
     * Truncates an instant to the precision the schema can actually store.
     *
     * @param instant the value to store, may be {@code null}
     * @return the truncated value, or {@code null} when the input was {@code null}
     */
    public static Instant truncate(Instant instant) {
        return instant == null ? null : instant.truncatedTo(STORAGE_PRECISION);
    }

    /**
     * Current instant already truncated to the storage precision.
     *
     * @return a value safe to persist
     */
    public static Instant now() {
        return truncate(Instant.now());
    }
}
