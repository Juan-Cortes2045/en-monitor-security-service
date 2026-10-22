package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.repository.UserDirectoryRow;
import com.energymonitor.security.adapter.out.persistence.repository.UserRepository;
import com.energymonitor.security.application.port.out.UserDirectoryPort;
import java.util.Locale;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;

/**
 * Reads the user directory with a single projection query per page.
 */
@Component
public class UserDirectoryAdapter implements UserDirectoryPort {

    private final UserRepository repository;

    public UserDirectoryAdapter(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public Page search(String text, int page, int size) {
        var rows = repository.searchDirectory(pattern(text), PageRequest.of(page, size));
        return new Page(rows.getContent().stream().map(UserDirectoryAdapter::toEntry).toList(),
                rows.getTotalElements());
    }

    /** A contains-match; {@code %} and {@code _} typed by the caller are matched literally. */
    static String pattern(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        String escaped = text.strip().toLowerCase(Locale.ROOT)
                .replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
        return "%" + escaped + "%";
    }

    private static Entry toEntry(UserDirectoryRow row) {
        return new Entry(row.idUser(), row.email(), row.name(), row.lastName(), row.status(),
                row.emailVerified(), row.registrationDate(), row.lastLoginAt());
    }
}
