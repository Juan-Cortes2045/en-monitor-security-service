package com.energymonitor.security.domain.model;

import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Email address of a {@link User}. Immutable value object.
 *
 * <p>Exists instead of a raw {@code String} because an address has rules of its own: it cannot
 * be blank, must have a plausible shape, and must be compared case-insensitively so that
 * {@code Ana@x.com} and {@code ana@x.com} cannot both register the account (INV-003).
 *
 * <p>Also normalises to lower case, which keeps the uniqueness check in
 * {@code uk_user_email} meaningful.
 */
public final class Email {

    /** Deliberately permissive: authoritative mail validation is a transport concern. */
    private static final Pattern FORMAT = Pattern.compile("^[^@\\s]+@[^@\\s.]+(\\.[^@\\s.]+)+$");

    /** Matches {@code user.email VARCHAR(255)}. */
    private static final int MAX_LENGTH = 255;

    private final String value;

    private Email(String value) {
        this.value = value;
    }

    /**
     * Creates an email from a raw string, normalising case.
     *
     * <p>Normalisation runs first so that both the length limit and the format check apply to
     * the value that is actually stored. Validating the raw input instead would count the
     * surrounding whitespace against the column, so an address that fits would be rejected
     * for a difference that the domain is about to discard anyway.
     *
     * @param raw the address; trimmed and lower-cased
     * @return the validated email
     * @throws IllegalArgumentException if blank, too long, or not shaped like an address
     */
    public static Email of(String raw) {
        Preconditions.notNull(raw, "email");
        String normalised = raw.trim().toLowerCase(Locale.ROOT);
        Preconditions.text(normalised, MAX_LENGTH, "email");
        if (!FORMAT.matcher(normalised).matches()) {
            throw new IllegalArgumentException("email is not a valid address: " + raw);
        }
        return new Email(normalised);
    }

    /** @return the normalised address */
    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Email email)) {
            return false;
        }
        return value.equals(email.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
