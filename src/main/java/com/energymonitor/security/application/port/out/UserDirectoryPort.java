package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.UserStatus;
import java.time.Instant;
import java.util.List;

/**
 * Output port for reading the active accounts as a searchable directory.
 *
 * <p>Separate from {@link UserPersistencePort} because it reads a projection, not the
 * {@code User} aggregate: listing accounts must not load every profile image.
 */
public interface UserDirectoryPort {

    /**
     * Finds active accounts, newest first.
     *
     * @param text matched, case-insensitively, against the address, name and last name;
     *             {@code null} or blank lists every account
     * @param page zero-based page number
     * @param size page size
     * @return the matching entries on that page and the total match count
     */
    Page search(String text, int page, int size);

    /**
     * One account as the directory shows it.
     *
     * @param idUser        the account
     * @param email         the account address
     * @param name          first name
     * @param lastName      last name, may be {@code null}
     * @param status        account state
     * @param emailVerified whether the address has been confirmed
     * @param registeredAt  when the account was registered
     * @param lastLoginAt   last successful login, may be {@code null}
     */
    record Entry(String idUser, String email, String name, String lastName, UserStatus status,
                 boolean emailVerified, Instant registeredAt, Instant lastLoginAt) {
    }

    /**
     * @param entries    the entries on the page
     * @param totalItems entries matching across all pages
     */
    record Page(List<Entry> entries, long totalItems) {

        public Page {
            entries = List.copyOf(entries);
        }
    }
}
