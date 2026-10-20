package com.energymonitor.security.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * JPA mapping of the {@code person} table.
 *
 * <p>Plain mapping, no associations. {@code person} has no outgoing foreign keys, so there is
 * nothing to link to.
 */
@Entity
@Table(name = "person")
public class PersonEntity extends BaseAuditEntity {

    @Id
    @Column(name = "id_person", nullable = false, length = 10)
    private String idPerson;

    @Column(name = "name", nullable = false, length = 100)
    private String name;

    @Column(name = "last_name", length = 100)
    private String lastName;

    public PersonEntity() {
    }

    public String getIdPerson() {
        return idPerson;
    }

    public void setIdPerson(String idPerson) {
        this.idPerson = idPerson;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

}
