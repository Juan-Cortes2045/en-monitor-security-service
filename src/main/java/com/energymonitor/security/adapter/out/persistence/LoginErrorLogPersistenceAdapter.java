package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.LoginErrorLogEntity;
import com.energymonitor.security.adapter.out.persistence.mapper.LoginErrorLogMapper;
import com.energymonitor.security.adapter.out.persistence.repository.LoginErrorLogRepository;
import com.energymonitor.security.application.port.out.LoginErrorLogPersistencePort;
import com.energymonitor.security.domain.model.LoginErrorLog;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for {@link LoginErrorLog}.
 *
 * <p>Failed attempts are append-only. A new entry is inserted with its business event time in
 * {@code created_at}; existing rows are never edited, matching the immutable domain object.
 */
@Component
public class LoginErrorLogPersistenceAdapter implements LoginErrorLogPersistencePort {

    private final LoginErrorLogRepository repository;
    private final LoginErrorLogMapper mapper;

    public LoginErrorLogPersistenceAdapter(LoginErrorLogRepository repository,
            LoginErrorLogMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Inserts a failed-attempt record.
     *
     * @param log the domain object
     * @return the same domain object
     */
    public LoginErrorLog save(LoginErrorLog log) {
        repository.save(mapper.toEntity(log));
        return log;
    }

    /**
     * Finds the active entry by identifier.
     *
     * @param idLoginError the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    public Optional<LoginErrorLog> findActive(String idLoginError) {
        return repository.findById(idLoginError)
                .filter(entity -> entity.getDeletedAt() == null)
                .map(mapper::toDomain);
    }

    /**
     * Lists every logged failure, newest first.
     *
     * @return the failures
     */
    public List<LoginErrorLog> listNewestFirst() {
        return repository.findAll().stream()
                .filter(entity -> entity.getDeletedAt() == null)
                .sorted((left, right) -> right.getCreatedAt().compareTo(left.getCreatedAt()))
                .map(mapper::toDomain)
                .toList();
    }
}