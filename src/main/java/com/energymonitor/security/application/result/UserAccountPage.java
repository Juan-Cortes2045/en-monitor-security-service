package com.energymonitor.security.application.result;

import java.util.List;

/**
 * A page of the user directory.
 *
 * @param items      the accounts on this page
 * @param page       zero-based page number
 * @param size       requested page size
 * @param totalItems accounts matching the search across all pages
 */
public record UserAccountPage(List<UserAccountSummary> items, int page, int size,
                              long totalItems) {

    public UserAccountPage {
        items = List.copyOf(items);
    }
}
