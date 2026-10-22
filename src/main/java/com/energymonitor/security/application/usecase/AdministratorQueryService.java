package com.energymonitor.security.application.usecase;

import com.energymonitor.security.api.AdministratorQuery;
import com.energymonitor.security.application.port.out.SystemRolePersistencePort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.application.port.out.UserSystemRolePersistencePort;
import com.energymonitor.security.domain.model.PermissionCodes;
import com.energymonitor.security.domain.model.SystemRole;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserSystemRole;
import java.util.List;

/**
 * Lists the accounts that hold the enabled {@code ADMIN} role and can sign in.
 */
public class AdministratorQueryService implements AdministratorQuery {

    private final SystemRolePersistencePort rolePort;
    private final UserSystemRolePersistencePort assignmentPort;
    private final UserPersistencePort userPort;

    public AdministratorQueryService(SystemRolePersistencePort rolePort,
                                     UserSystemRolePersistencePort assignmentPort,
                                     UserPersistencePort userPort) {
        this.rolePort = rolePort;
        this.assignmentPort = assignmentPort;
        this.userPort = userPort;
    }

    @Override
    public List<String> activeAdministratorIds() {
        return rolePort.findActiveByName(PermissionCodes.ADMIN_ROLE)
                .filter(SystemRole::canBeAssigned)
                .map(role -> assignmentPort.listActiveBySystemRole(role.idSystemRole()).stream()
                        .map(UserSystemRole::idUser)
                        .filter(id -> userPort.findActive(id).filter(User::canAuthenticate).isPresent())
                        .distinct()
                        .toList())
                .orElse(List.of());
    }
}
