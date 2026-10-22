package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.CheckPermissionQuery;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.CheckPermission;
import com.energymonitor.security.application.port.out.PermissionPersistencePort;
import com.energymonitor.security.application.port.out.SystemRolePermissionPersistencePort;
import com.energymonitor.security.application.port.out.SystemRolePersistencePort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.application.port.out.UserSystemRolePersistencePort;
import com.energymonitor.security.domain.model.Permission;
import com.energymonitor.security.domain.model.SystemRole;
import com.energymonitor.security.domain.model.SystemRolePermission;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserSystemRole;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Authorizes a user against a permission code through the RBAC chain
 * {@code User → UserSystemRole → SystemRole → SystemRolePermission → Permission}.
 *
 * <p>Both the single-code check and the full list of granted codes come out of the same walk of
 * that chain, so the list a client is handed always agrees with what an enforcement point would
 * decide for any code in it.
 */
public class CheckPermissionService implements CheckPermission {

    private final UserPersistencePort userPort;
    private final PermissionPersistencePort permissionPort;
    private final SystemRolePersistencePort rolePort;
    private final UserSystemRolePersistencePort userSystemRolePort;
    private final SystemRolePermissionPersistencePort systemRolePermissionPort;

    public CheckPermissionService(UserPersistencePort userPort,
                                  PermissionPersistencePort permissionPort,
                                  SystemRolePersistencePort rolePort,
                                  UserSystemRolePersistencePort userSystemRolePort,
                                  SystemRolePermissionPersistencePort systemRolePermissionPort) {
        this.userPort = userPort;
        this.permissionPort = permissionPort;
        this.rolePort = rolePort;
        this.userSystemRolePort = userSystemRolePort;
        this.systemRolePermissionPort = systemRolePermissionPort;
    }

    @Override
    public boolean check(CheckPermissionQuery query) {
        Set<String> granted = grantedPermissionIds(query.idUser());
        Permission permission = permissionPort.findActiveByCode(query.permissionCode()).orElse(null);
        return permission != null && granted.contains(permission.idPermission());
    }

    @Override
    public List<String> listGrantedCodes(String idUser) {
        Set<String> granted = grantedPermissionIds(idUser);
        return permissionPort.findAllActive().stream()
                .filter(permission -> granted.contains(permission.idPermission()))
                .map(Permission::code)
                .sorted()
                .toList();
    }

    /**
     * Resolves the RBAC chain once and answers with the permission identifiers the user holds.
     *
     * <p>This is the single place the chain is walked, so {@link #check} and
     * {@link #listGrantedCodes} cannot drift apart: two implementations of one authorization rule
     * would eventually disagree, and the one that says "granted" is the one that opens a door.
     *
     * <p>An account that cannot authenticate is refused by returning nothing rather than by
     * throwing: the caller is authenticated, but not entitled to anything, and "holds no
     * permission" is the honest answer for a blocked account.
     *
     * @param idUser the user
     * @return the granted permission identifiers, empty when the account holds none or cannot
     *         authenticate
     * @throws UserNotFoundException when no active account carries that identifier
     */
    private Set<String> grantedPermissionIds(String idUser) {
        User user = userPort.findActive(idUser)
                .orElseThrow(() -> new UserNotFoundException("no active user " + idUser));
        if (!user.canAuthenticate()) {
            return Set.of();
        }
        return userSystemRolePort.listActiveByUser(user.idUser()).stream()
                .map(UserSystemRole::idSystemRole)
                .filter(this::isAssignedRoleEnabled)
                .flatMap(roleId -> systemRolePermissionPort.listActiveBySystemRole(roleId).stream())
                .map(SystemRolePermission::idPermission)
                .collect(Collectors.toSet());
    }

    private boolean isAssignedRoleEnabled(String idSystemRole) {
        return rolePort.findActive(idSystemRole)
                .filter(SystemRole::canBeAssigned)
                .isPresent();
    }
}