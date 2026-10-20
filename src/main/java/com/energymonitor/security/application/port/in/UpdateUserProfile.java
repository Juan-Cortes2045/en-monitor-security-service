package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.UpdateUserProfileCommand;
import com.energymonitor.security.domain.model.Person;

/**
 * Input port for editing the personal data of a user, and optionally their account email and avatar.
 */
public interface UpdateUserProfile {

    /**
     * @param command the profile data
     * @return the edited person
     */
    Person update(UpdateUserProfileCommand command);
}