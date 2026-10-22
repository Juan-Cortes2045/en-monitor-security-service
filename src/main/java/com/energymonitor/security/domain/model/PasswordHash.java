package com.energymonitor.security.domain.model;

import java.util.Objects;

/**
 * Already-hashed password of a {@link User}. Immutable value object.
 *
 * <p>The domain never sees a plain-text password and never hashes anything itself: the
 * algorithm belongs to the security adapter, which will produce this value (INV-004).
 *
 * <p>{@link #toString()} is overridden to return a fixed mask so a hash cannot leak into a
 * log line or a stack trace through string concatenation.
 */
public final class PasswordHash {

    /** Matches {@code user.password_hash VARCHAR(255)}; 60 chars covers BCrypt. */
    private static final int MAX_LENGTH = 255;

    private static final String MASK = "********";

    private final String value;

    private PasswordHash(String value) {
        this.value = value;
    }

    /**
     * Wraps an existing hash.
     *
     * @param alreadyHashed a non-blank hash produced by the security adapter
     * @return the wrapped hash
     * @throws IllegalArgumentException if blank or longer than the column allows
     */
    public static PasswordHash of(String alreadyHashed) {
        Preconditions.text(alreadyHashed, MAX_LENGTH, "passwordHash");
        return new PasswordHash(alreadyHashed);
    }

    /**
     * Exposes the hash for the security adapter to compare against.
     *
     * <p>Only the adapter performing password verification should call this.
     *
     * @return the stored hash
     */
    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof PasswordHash that)) {
            return false;
        }
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return MASK;
    }
}
