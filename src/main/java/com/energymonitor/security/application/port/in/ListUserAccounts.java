package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.ListUserAccountsQuery;
import com.energymonitor.security.application.result.UserAccountPage;
import com.energymonitor.security.domain.model.SystemRole;
import java.util.List;

/**
 * Input port for reading the user directory and the role catalogue.
 *
 * <p>Holds no authorization of its own: the filter chain lets only callers holding
 * {@code USER.READ} reach it.
 */
public interface ListUserAccounts {

    /**
     * @param query the search and the page
     * @return the matching accounts with their global roles
     */
    UserAccountPage list(ListUserAccountsQuery query);

    /**
     * @return the global roles that can be granted, sorted by name
     */
    List<SystemRole> listAssignableRoles();
}
