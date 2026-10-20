package com.energymonitor.security.infrastructure;

import com.energymonitor.security.application.command.CheckPermissionQuery;
import com.energymonitor.security.application.exception.UserNotFoundException;
import com.energymonitor.security.application.port.in.CheckPermission;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

/**
 * Enforces a global permission code on a route, through the same RBAC walk that
 * {@code GET /api/v1/auth/permissions} publishes.
 *
 * <p>The permissions are resolved from the database on every request rather than carried in
 * the access token. A role granted or revoked, or an account blocked, therefore takes effect on
 * the next request instead of when the token expires, at the cost of a few indexed reads per
 * administration call.
 *
 * <p>An anonymous caller is denied, which the filter chain turns into 401; an authenticated
 * caller without the code, or whose account is gone, is denied with 403.
 */
@Component
public class PermissionAuthorization {

    private final CheckPermission checkPermission;

    public PermissionAuthorization(CheckPermission checkPermission) {
        this.checkPermission = checkPermission;
    }

    /**
     * @param permissionCode the code the caller must hold
     * @return a rule granting access only to callers holding that code
     */
    public AuthorizationManager<RequestAuthorizationContext> require(String permissionCode) {
        return (authentication, context) ->
                new AuthorizationDecision(holds(authentication.get(), permissionCode));
    }

    private boolean holds(Authentication authentication, String permissionCode) {
        if (authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return false;
        }
        try {
            return checkPermission.check(
                    new CheckPermissionQuery(authentication.getName(), permissionCode));
        } catch (UserNotFoundException gone) {
            return false;
        }
    }
}
