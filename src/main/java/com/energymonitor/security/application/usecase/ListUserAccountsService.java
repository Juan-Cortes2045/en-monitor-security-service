package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.command.ListUserAccountsQuery;
import com.energymonitor.security.application.port.in.ListUserAccounts;
import com.energymonitor.security.application.port.out.SystemRolePersistencePort;
import com.energymonitor.security.application.port.out.UserDirectoryPort;
import com.energymonitor.security.application.port.out.UserSystemRolePersistencePort;
import com.energymonitor.security.application.result.UserAccountPage;
import com.energymonitor.security.application.result.UserAccountSummary;
import com.energymonitor.security.domain.model.SystemRole;
import com.energymonitor.security.domain.model.UserSystemRole;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Reads the user directory with the global roles of each account.
 */
public class ListUserAccountsService implements ListUserAccounts {

    private final UserDirectoryPort directory;
    private final UserSystemRolePersistencePort assignmentPort;
    private final SystemRolePersistencePort rolePort;

    public ListUserAccountsService(UserDirectoryPort directory,
                                   UserSystemRolePersistencePort assignmentPort,
                                   SystemRolePersistencePort rolePort) {
        this.directory = directory;
        this.assignmentPort = assignmentPort;
        this.rolePort = rolePort;
    }

    @Override
    public UserAccountPage list(ListUserAccountsQuery query) {
        UserDirectoryPort.Page found = directory.search(query.text(), query.page(), query.size());
        Map<String, String> roleNames = rolePort.findAllActive().stream()
                .collect(Collectors.toMap(SystemRole::idSystemRole, SystemRole::name));
        // ponytail: one role lookup per account on the page; the page holds at most 50.
        List<UserAccountSummary> items = found.entries().stream()
                .map(entry -> new UserAccountSummary(entry.idUser(), entry.email(), entry.name(),
                        entry.lastName(), entry.status(), entry.emailVerified(),
                        entry.registeredAt(), entry.lastLoginAt(),
                        rolesOf(entry.idUser(), roleNames)))
                .toList();
        return new UserAccountPage(items, query.page(), query.size(), found.totalItems());
    }

    @Override
    public List<SystemRole> listAssignableRoles() {
        return rolePort.findAllActive().stream()
                .filter(SystemRole::canBeAssigned)
                .sorted(Comparator.comparing(SystemRole::name))
                .toList();
    }

    private List<String> rolesOf(String idUser, Map<String, String> roleNames) {
        return assignmentPort.listActiveByUser(idUser).stream()
                .map(UserSystemRole::idSystemRole)
                .map(roleNames::get)
                .filter(Objects::nonNull)
                .sorted()
                .distinct()
                .toList();
    }
}
