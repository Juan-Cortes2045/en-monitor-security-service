package com.energymonitor.security.infrastructure;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

/**
 * Decides whether a request to {@code /internal/**} comes from energy-monitor-backend: it must
 * come from an allowed network <em>and</em> carry the shared token. Either one alone is not
 * enough, since any container on the Docker network passes the first check.
 *
 * <p>With no token configured nothing is trusted, so a deployment that forgot it fails closed.
 */
public class InternalCallerCheck {

    private final byte[] token;
    private final List<IpAddressMatcher> networks;

    public InternalCallerCheck(InternalApiProperties properties) {
        String configured = properties.token();
        this.token = configured == null || configured.isBlank()
                ? null : configured.getBytes(StandardCharsets.UTF_8);
        this.networks = properties.allowedNetworks().stream()
                .map(String::trim)
                .filter(network -> !network.isEmpty())
                .map(IpAddressMatcher::new)
                .toList();
    }

    /**
     * @param request the inbound request
     * @return whether it may reach an internal endpoint
     */
    public boolean trusts(HttpServletRequest request) {
        if (token == null || networks.stream().noneMatch(network -> network.matches(request))) {
            return false;
        }
        String presented = request.getHeader(InternalApiProperties.TOKEN_HEADER);
        // Constant time, so the answer time says nothing about how much of the token matched.
        return presented != null
                && MessageDigest.isEqual(token, presented.getBytes(StandardCharsets.UTF_8));
    }
}
