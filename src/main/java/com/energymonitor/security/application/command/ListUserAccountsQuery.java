package com.energymonitor.security.application.command;

/**
 * Input of {@code ListUserAccounts}: one page of the user directory.
 *
 * @param text optional search over address, name and last name
 * @param page zero-based page number, not negative
 * @param size page size, between 1 and {@link #MAX_SIZE}
 */
public record ListUserAccountsQuery(String text, int page, int size) {

    /** Largest page a caller may ask for. */
    public static final int MAX_SIZE = 50;

    public ListUserAccountsQuery {
        if (page < 0) {
            throw new IllegalArgumentException("page must not be negative");
        }
        if (size < 1 || size > MAX_SIZE) {
            throw new IllegalArgumentException("size must be between 1 and " + MAX_SIZE);
        }
        text = text == null || text.isBlank() ? null : text.strip();
    }
}
