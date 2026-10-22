package com.energymonitor.security.api;

import java.util.Collection;
import java.util.Map;

/**
 * Read-only lookup of account profiles for other modules, such as the members of a home.
 *
 * <p>It answers who an identifier belongs to and nothing else. Deciding whether the caller may see
 * those accounts is the asking module's job: this module does not know homes or memberships.
 */
public interface UserProfileQuery {

    /**
     * Looks up the profiles of the given accounts.
     *
     * @param userIds account identifiers; duplicates and unknown ones are fine
     * @return the profile of every active account found, keyed by its identifier; an identifier
     *         with no active account is simply absent
     */
    Map<String, UserProfile> findByIds(Collection<String> userIds);
}
