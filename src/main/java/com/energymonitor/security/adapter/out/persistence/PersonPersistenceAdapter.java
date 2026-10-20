package com.energymonitor.security.adapter.out.persistence;

import com.energymonitor.security.adapter.out.persistence.entity.PersonEntity;
import com.energymonitor.security.adapter.out.persistence.mapper.PersonMapper;
import com.energymonitor.security.adapter.out.persistence.repository.PersonRepository;
import com.energymonitor.security.application.port.out.PersonPersistencePort;
import com.energymonitor.security.domain.model.Person;
import java.time.Instant;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Persistence adapter for {@link Person}, exposing the domain object and hiding entity and
 * repository details.
 */
@Component
public class PersonPersistenceAdapter implements PersonPersistencePort {

    private final PersonRepository repository;
    private final PersonMapper mapper;

    public PersonPersistenceAdapter(PersonRepository repository, PersonMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Inserts or updates the person.
     *
     * @param person the domain object
     * @return the same domain object
     */
    public Person save(Person person) {
        repository.save(mapper.toEntity(person));
        return person;
    }

    /**
     * Finds the active person by identifier.
     *
     * @param idPerson the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    public Optional<Person> findActive(String idPerson) {
        return repository.findById(idPerson)
                .filter(entity -> entity.getDeletedAt() == null)
                .map(mapper::toDomain);
    }

    @Override
    public void softDelete(String idPerson, Instant deletedAt) {
        repository.findById(idPerson).ifPresent(entity -> {
            entity.setDeletedAt(deletedAt);
            repository.save(entity);
        });
    }
}
