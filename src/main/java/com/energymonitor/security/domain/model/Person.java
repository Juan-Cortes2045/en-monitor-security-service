package com.energymonitor.security.domain.model;

import java.util.Objects;

/**
 * Personal identity of a human being. Aggregate root of its own small aggregate.
 *
 * <p>Holds personal data only. It deliberately stores no credentials, tokens or account state:
 * authentication belongs to {@link User} (INV-002). This separation is what lets the same
 * person's data exist without an account.
 *
 * <p>It also holds nothing that describes the <em>account</em> rather than the human being.
 * The profile image belongs to {@link User}, because it is the avatar a client renders for an
 * account and is stored as long as the account exists. The residential address was removed
 * outright: it duplicated {@code home.address}, which the home module owns and where the
 * address a user actually occupies belongs.
 *
 * <p>What is left is what can only ever describe the person: their name.
 *
 * <p>The phone number was removed alongside it. Notifications are email only, so a contact
 * channel that nothing delivers to has no reason to be stored against a person.
 *
 * <p>Maps to the {@code person} table.
 */
public class Person {

    private static final int NAME_MAX = 100;

    private final String idPerson;
    private String name;
    private String lastName;

    /**
     * @param idPerson identifier, {@code VARCHAR(10)}
     * @param name     first name, required (INV-001)
     * @param lastName last name, optional: an account created from Google may have none
     */
    public Person(String idPerson, String name, String lastName) {
        this.idPerson = Preconditions.text(idPerson, "idPerson");
        this.name = Preconditions.text(name, NAME_MAX, "name");
        this.lastName = Preconditions.optionalText(lastName, NAME_MAX, "lastName");
    }

    /** @return the identifier */
    public String idPerson() {
        return idPerson;
    }

    /** @return first name */
    public String name() {
        return name;
    }

    /** @return last name */
    public String lastName() {
        return lastName;
    }

    /**
     * Replaces the first and last name.
     *
     * @param name     new first name
     * @param lastName new last name
     */
    public void rename(String name, String lastName) {
        this.name = Preconditions.text(name, NAME_MAX, "name");
        this.lastName = Preconditions.optionalText(lastName, NAME_MAX, "lastName");
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Person person)) {
            return false;
        }
        return idPerson.equals(person.idPerson);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idPerson);
    }

    @Override
    public String toString() {
        return "Person{idPerson='" + idPerson + "'}";
    }
}
