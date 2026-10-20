package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.command.CheckPermissionQuery;
import java.util.List;

/**
 * Input port for authorizing a user against the permission codes they hold.
 *
 * <p>Two questions, one rule. {@link #check(CheckPermissionQuery)} answers about a single code,
 * which is what an enforcement point needs. {@link #listGrantedCodes(String)} answers about the
 * whole set at once, which is what a client needs to build a menu or a route guard without
 * calling the first method once per code it knows about.
 *
 * <p>Both are served from the same resolution of the RBAC chain
 * {@code User → UserSystemRole → SystemRole → SystemRolePermission → Permission}, so the answer
 * to "may this user do X" can never disagree with the list the same user was handed.
 */
public interface CheckPermission {

    /**
     * @param query the user and the permission to test
     * @return {@code true} when the user holds the permission through an enabled role
     */
    boolean check(CheckPermissionQuery query);

    /**
     * Lists every permission code the user currently holds.
     *
     * <p>The codes, not the identifiers, because the code is the stable contract (INV-022): a
     * client hard-codes it and it must survive a reseed of the {@code permission} table.
     *
     * @param idUser the user
     * @return the granted codes, sorted and without duplicates; empty when the user holds no
     *         permission or cannot authenticate
     * @throws com.energymonitor.security.application.exception.UserNotFoundException when no
     *         active account carries that identifier
     */
    List<String> listGrantedCodes(String idUser);
}
