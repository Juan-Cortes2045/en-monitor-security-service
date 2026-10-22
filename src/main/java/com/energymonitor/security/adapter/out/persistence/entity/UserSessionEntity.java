package com.energymonitor.security.adapter.out.persistence.entity;

import com.energymonitor.security.domain.model.RevocationReason;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * JPA mapping of the {@code user_session} table.
 *
 * <p>Both lifecycle flags are first-class columns. {@code revoked} and {@code closed_at} are
 * rehydrated as persisted, so a revoked or closed session can never come back from the
 * database looking usable.
 */
@Entity
@Table(name = "user_session")
public class UserSessionEntity extends BaseAuditEntity {

    @Id
    @Column(name = "id_user_session", nullable = false, length = 10)
    private String idUserSession;

    @Column(name = "user_id", nullable = false, length = 10)
    private String userId;

    @Column(name = "revoked", nullable = false)
    @TinyIntBoolean
    private boolean revoked;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 150)
    private String userAgent;

    @Column(name = "expiration_at", nullable = false)
    private Instant expirationAt;

    @Column(name = "closed_at")
    private Instant closedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "revoked_reason")
    private RevocationReason revokedReason;

    public UserSessionEntity() {
    }

    public String getIdUserSession() {
        return idUserSession;
    }

    public void setIdUserSession(String idUserSession) {
        this.idUserSession = idUserSession;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public Instant getExpirationAt() {
        return expirationAt;
    }

    public void setExpirationAt(Instant expirationAt) {
        this.expirationAt = expirationAt;
    }

    public Instant getClosedAt() {
        return closedAt;
    }

    public void setClosedAt(Instant closedAt) {
        this.closedAt = closedAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(Instant revokedAt) {
        this.revokedAt = revokedAt;
    }

    public RevocationReason getRevokedReason() {
        return revokedReason;
    }

    public void setRevokedReason(RevocationReason revokedReason) {
        this.revokedReason = revokedReason;
    }
}
