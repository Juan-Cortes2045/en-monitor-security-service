package com.energymonitor.security.application.command;

/**
 * Input of {@code CheckPermission}: asks whether a user holds a permission, directly or
 * through the enabled global roles assigned to them.
 *
 * @param idUser        the user
 * @param permissionCode the stable permission code to test
 */
public record CheckPermissionQuery(String idUser, String permissionCode) {
}