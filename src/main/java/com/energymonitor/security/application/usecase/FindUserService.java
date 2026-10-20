package com.energymonitor.security.application.usecase;

import com.energymonitor.security.application.port.in.FindUser;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.User;
import java.util.Optional;

/**
 * Reads account state.
 */
public class FindUserService implements FindUser {

    private final UserPersistencePort userPort;

    public FindUserService(UserPersistencePort userPort) {
        this.userPort = userPort;
    }

    @Override
    public Optional<User> findByIdentifier(String idUser) {
        return userPort.findActive(idUser);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userPort.findActiveByEmail(Email.of(email));
    }
}