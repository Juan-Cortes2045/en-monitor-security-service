package com.energymonitor.security.api;

import java.util.List;

/**
 * Who the platform administrators are, for modules that address them, such as the notification
 * module delivering administrator notifications.
 */
public interface AdministratorQuery {

    /**
     * @return the accounts holding the global {@code ADMIN} role that can currently sign in
     */
    List<String> activeAdministratorIds();
}
