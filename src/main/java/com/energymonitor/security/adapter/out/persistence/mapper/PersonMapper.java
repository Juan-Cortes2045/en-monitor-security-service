package com.energymonitor.security.adapter.out.persistence.mapper;

import com.energymonitor.security.adapter.out.persistence.entity.PersonEntity;
import com.energymonitor.security.domain.model.Person;
import org.springframework.stereotype.Component;

/**
 * Converts {@link Person} to and from {@link PersonEntity}.
 *
 * <p>The optional contact fields are {@code Optional} in the domain and {@code null} in the
 * column, so this mapper is where the two representations meet. Mappers hold no business
 * rules; they only translate representation.
 */
@Component
public class PersonMapper {

    /**
     * Builds a new entity from the domain object.
     *
     * @param person the domain object
     * @return a detached entity ready to be persisted
     */
    public PersonEntity toEntity(Person person) {
        PersonEntity entity = new PersonEntity();
        applyTo(entity, person);
        return entity;
    }

    /**
     * Copies the domain state onto an already managed entity, for updates.
     *
     * @param entity the managed entity
     * @param person the domain object holding the new state
     */
    public void applyTo(PersonEntity entity, Person person) {
        entity.setIdPerson(person.idPerson());
        entity.setName(person.name());
        entity.setLastName(person.lastName());
    }

    /**
     * Rehydrates the domain object from a stored row.
     *
     * @param entity the stored row
     * @return the domain object
     */
    public Person toDomain(PersonEntity entity) {
        return new Person(entity.getIdPerson(), entity.getName(), entity.getLastName());
    }
}
