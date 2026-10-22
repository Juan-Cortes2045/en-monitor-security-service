package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.domain.model.UserStatus;
import java.time.Instant;

/**
 * Projection of an account and its person for the user directory, built by the query itself so
 * the profile image column is never read.
 */
public record UserDirectoryRow(String idUser, String email, String name, String lastName,
                               UserStatus status, boolean emailVerified, Instant registrationDate,
                               Instant lastLoginAt) {
}
