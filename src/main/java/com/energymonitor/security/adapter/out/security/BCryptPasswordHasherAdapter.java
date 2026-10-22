package com.energymonitor.security.adapter.out.security;

import com.energymonitor.security.application.port.out.PasswordHasherPort;
import com.energymonitor.security.domain.model.PasswordHash;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * BCrypt implementation of {@link PasswordHasherPort}.
 *
 * <p>The application layer reaches password hashing only through the port, so neither the
 * use cases nor the domain ever see {@link BCryptPasswordEncoder}; the algorithm, its cost
 * factor and the salt handling stay here. BCrypt salts every hash internally, so the same
 * password hashes differently on every call and verification is done by recomputing the
 * hash with the salt embedded in the stored value.
 *
 * <p>The default cost factor (10) is used deliberately: it is Spring Security's current
 * default and lands in the 60-character encoded form the {@code password_hash VARCHAR(255)}
 * column stores with room to spare.
 */
@Component
public class BCryptPasswordHasherAdapter implements PasswordHasherPort {

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @Override
    public PasswordHash hash(String rawPassword) {
        return PasswordHash.of(encoder.encode(rawPassword));
    }

    @Override
    public boolean matches(String rawPassword, PasswordHash passwordHash) {
        try {
            return encoder.matches(rawPassword, passwordHash.value());
        } catch (IllegalArgumentException notBcrypt) {
            // The stored value is not a BCrypt hash: a hand-seeded row or a hash written by
            // some other algorithm. It can never match, and it must not surface as a 500.
            return false;
        }
    }
}
