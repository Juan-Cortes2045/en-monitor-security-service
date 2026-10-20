package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.Person;
import java.time.Instant;
import java.util.Optional;

/**
 * Output port for persisting {@link Person}.
 */
public interface PersonPersistencePort {

    /**
     * Inserts or updates the person.
     *
     * @param person the domain object
     * @return the same domain object
     */
    Person save(Person person);

    /**
     * Finds the active person by identifier.
     *
     * @param idPerson the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    Optional<Person> findActive(String idPerson);

    /**
     * Marks the person as deleted. Its row stays; {@code findActive} stops returning it.
     *
     * @param idPerson the identifier
     * @param deletedAt when it was deleted
     */
    void softDelete(String idPerson, Instant deletedAt);
}
