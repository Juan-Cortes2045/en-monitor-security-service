package com.energymonitor.security.application;

import com.energymonitor.security.application.port.out.RefreshTokenHasherPort;
import com.energymonitor.security.application.port.out.RefreshTokenPersistencePort;
import com.energymonitor.security.domain.model.RefreshToken;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * In-memory fakes of the refresh-token output ports, for application-layer tests only.
 *
 * <p>They stand in for the persistence adapter and the SHA-256 adapter so the refresh flow can
 * be exercised without a database, while still going through the real port methods the
 * production code calls.
 */
final class RefreshTokenFixtures {

    private RefreshTokenFixtures() {
    }

    /**
     * Keeps generations in a map keyed by hash, exactly as the real store resolves them, so a
     * test that passes here would pass against MySQL for the same reason.
     */
    static final class FakeRefreshTokenPersistencePort implements RefreshTokenPersistencePort {

        private final Map<String, RefreshToken> byHash = new LinkedHashMap<>();
        private final Map<String, RefreshToken> byId = new LinkedHashMap<>();

        /** When set, {@link #save} throws it, to simulate a failure mid-rotation. */
        private RuntimeException failOnSave;

        @Override
        public RefreshToken save(RefreshToken token) {
            if (failOnSave != null) {
                throw failOnSave;
            }
            byHash.put(token.tokenHash(), token);
            byId.put(token.idRefreshToken(), token);
            return token;
        }

        @Override
        public Optional<RefreshToken> findByTokenHash(String tokenHash) {
            return Optional.ofNullable(byHash.get(tokenHash));
        }

        @Override
        public List<RefreshToken> listByFamily(String familyId) {
            return byId.values().stream()
                    .filter(token -> token.familyId().equals(familyId))
                    .toList();
        }

        void failSavesWith(RuntimeException failure) {
            this.failOnSave = failure;
        }

        List<RefreshToken> all() {
            return new ArrayList<>(byId.values());
        }

        int size() {
            return byId.size();
        }

        int countWithStatus(com.energymonitor.security.domain.model.RefreshTokenStatus status) {
            return (int) byId.values().stream().filter(token -> token.status() == status).count();
        }
    }

    /**
     * Stands in for SHA-256 with a reversible prefix, so a test can assert which generation a
     * secret resolves to without reproducing a digest in test code.
     */
    static final class FakeRefreshTokenHasher implements RefreshTokenHasherPort {

        @Override
        public String hash(String rawToken) {
            if (rawToken == null || rawToken.isBlank()) {
                throw new IllegalArgumentException("rawToken must not be null or blank");
            }
            return "hash:" + rawToken;
        }
    }
}
