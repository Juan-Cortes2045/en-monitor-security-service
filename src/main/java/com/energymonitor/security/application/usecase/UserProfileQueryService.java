package com.energymonitor.security.application.usecase;

import com.energymonitor.security.api.UserProfile;
import com.energymonitor.security.api.UserProfileQuery;
import com.energymonitor.security.application.port.out.PersonPersistencePort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Resolves account identifiers to the profile other modules may show.
 */
public class UserProfileQueryService implements UserProfileQuery {

    private final UserPersistencePort users;
    private final PersonPersistencePort persons;

    public UserProfileQueryService(UserPersistencePort users, PersonPersistencePort persons) {
        this.users = users;
        this.persons = persons;
    }

    @Override
    public Map<String, UserProfile> findByIds(Collection<String> userIds) {
        Map<String, UserProfile> profiles = new LinkedHashMap<>();
        // ponytail: two lookups per account; the callers ask for the members of one home or the
        // owners of one user's homes, a handful each. Add batch reads to the ports if that grows.
        userIds.stream().filter(Objects::nonNull).distinct().forEach(userId ->
                users.findActive(userId).ifPresent(user ->
                        persons.findActive(user.idPerson()).ifPresent(person ->
                                profiles.put(userId, new UserProfile(userId, person.name(),
                                        person.lastName(), user.email().value())))));
        return profiles;
    }
}
