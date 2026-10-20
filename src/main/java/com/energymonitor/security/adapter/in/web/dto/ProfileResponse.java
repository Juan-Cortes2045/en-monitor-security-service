package com.energymonitor.security.adapter.in.web.dto;

import com.energymonitor.security.domain.model.Person;

/**
 * The profile as it now stands, read back from the aggregate the use case saved.
 *
 * <p>These are the values that were written, not the ones that were asked for: the use case
 * returns the person it persisted, so a client that sent a name gets told what is actually
 * stored. The name can only differ from the request if something rejected it, and that
 * rejection is a failure rather than a silent correction.
 *
 * <p>The record carries the person only, because the person is all this use case returns. When a
 * caller also moves the account's email or avatar through the same request, those land on the
 * account and are read back from {@code GET /api/v1/auth/account}; echoing them here would mean
 * either a second lookup or a response that reports state the update did not return.
 *
 * <p>No phone number appears, exactly as in {@link UpdateProfileRequest}: the value was removed
 * from the model, so there is nothing to publish.
 *
 * @param idPerson the person identifier the name is stored against
 * @param name     the persisted first name
 * @param lastName the persisted last name
 */
public record ProfileResponse(String idPerson, String name, String lastName) {

    /**
     * Maps the aggregate returned by the profile update.
     *
     * @param person the persisted person
     * @return the public view
     */
    public static ProfileResponse from(Person person) {
        return new ProfileResponse(person.idPerson(), person.name(), person.lastName());
    }
}