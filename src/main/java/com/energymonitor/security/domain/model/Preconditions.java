package com.energymonitor.security.domain.model;

import java.time.Instant;

/**
 * Argument checks shared by the Security domain model.
 *
 * <p>Deliberately package-private and framework-free: the domain must stay plain Java.
 * Every failure is an {@link IllegalArgumentException}, so no custom exception hierarchy
 * is imposed on future phases.
 */
final class Preconditions {

    private Preconditions() {
    }

    static <T> T notNull(T value, String field) {
        if (value == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }
        return value;
    }

    static String text(String value, String field) {
        notNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    static String text(String value, int maxLength, String field) {
        text(value, field);
        if (value.length() > maxLength) {
            throw new IllegalArgumentException(field + " must be at most " + maxLength + " characters");
        }
        return value;
    }

    /**
     * Validates an optional text value.
     *
     * @param value     the value; {@code null} means absent
     * @param maxLength maximum accepted length
     * @param field     field name used in the error message
     * @return {@code null} when absent, the value otherwise
     */
    static String optionalText(String value, int maxLength, String field) {
        if (value == null) {
            return null;
        }
        return text(value, maxLength, field);
    }

    /**
     * Validates a validity window: an expiry must always be strictly after its creation.
     *
     * <p>Shared by every entity that carries a {@code created_at} / {@code expiration_at} pair,
     * so that issuing a value and rehydrating it from the database enforce the exact same
     * invariant. A window that is impossible is not a persistence problem to be tolerated, it
     * is an invalid object.
     *
     * @param createdAt    instant the object came into existence
     * @param expirationAt instant it stops being valid
     * @throws IllegalStateException if the expiration is not strictly after the creation
     */
    static void expirationAfter(Instant createdAt, Instant expirationAt) {
        notNull(createdAt, "createdAt");
        notNull(expirationAt, "expirationAt");
        if (!expirationAt.isAfter(createdAt)) {
            throw new IllegalStateException("expirationAt must be after createdAt");
        }
    }

    static int notNegative(int value, String field) {
        if (value < 0) {
            throw new IllegalArgumentException(field + " must not be negative");
        }
        return value;
    }

    static int positive(int value, String field) {
        if (value <= 0) {
            throw new IllegalArgumentException(field + " must be greater than zero");
        }
        return value;
    }
}
