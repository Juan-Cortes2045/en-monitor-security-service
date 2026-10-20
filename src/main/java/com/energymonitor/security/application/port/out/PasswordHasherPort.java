package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.PasswordHash;

/**
 * Output port for hashing passwords.
 *
 * <p>The concrete algorithm (e.g. BCrypt) belongs to the infrastructure adapter, see the
 * domain INV-004 handshake: the domain never hashes, it only wraps the already-computed
 * value, so this port produces the hashes the {@code User} aggregate expects.
 */
public interface PasswordHasherPort {

    /**
     * Hashes a raw password.
     *
     * @param rawPassword the plain-text candidate, never stored
     * @return the wrapped hash
     */
    PasswordHash hash(String rawPassword);

    /**
     * Whether a raw password matches a stored hash.
     *
     * @param rawPassword the plain-text candidate
     * @param passwordHash the stored hash
     * @return {@code true} when the candidate matches
     */
    boolean matches(String rawPassword, PasswordHash passwordHash);
}