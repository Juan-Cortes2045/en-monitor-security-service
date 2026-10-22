package com.energymonitor.security.adapter.out.persistence.entity;

import com.energymonitor.security.domain.model.RefreshTokenStatus;
import com.energymonitor.security.domain.model.RevocationReason;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * JPA mapping of {@code refresh_token}: one row per token generation.
 *
 * <p>Relationships are plain identifier columns rather than associations. The lineage
 * {@code parent_id} and {@code family_id} are only ever read as values, never navigated, so
 * modelling them as associations would add a bidirectional object graph to maintain and persist
 * without a single query needing it.
 *
 * <p>There is deliberately no field for the secret: the row holds {@code token_hash} and
 * nothing that could be turned back into a usable credential.
 */
@Entity
@Table(name = "refresh_token")
public class RefreshTokenEntity extends BaseAuditEntity {

    @Id
    @Column(name = "id_refresh_token", nullable = false, length = 10)
    private String idRefreshToken;

    @Column(name = "id_user_session", nullable = false, length = 10)
    private String idUserSession;

    @Column(name = "family_id", nullable = false, length = 10)
    private String familyId;

    @Column(name = "parent_id", length = 10)
    private String parentId;

    /** Lowercase hex SHA-256 of the secret. */
    @Column(name = "token_hash", nullable = false, length = 64, unique = true)
    private String tokenHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private RefreshTokenStatus status;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "rotated_at")
    private Instant rotatedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "revoked_reason")
    private RevocationReason revokedReason;

    /** @return the identifier */
    public String getIdRefreshToken() {
        return idRefreshToken;
    }

    /** @param idRefreshToken the identifier */
    public void setIdRefreshToken(String idRefreshToken) {
        this.idRefreshToken = idRefreshToken;
    }

    /** @return the owning session identifier */
    public String getIdUserSession() {
        return idUserSession;
    }

    /** @param idUserSession the owning session identifier */
    public void setIdUserSession(String idUserSession) {
        this.idUserSession = idUserSession;
    }

    /** @return the family root identifier */
    public String getFamilyId() {
        return familyId;
    }

    /** @param familyId the family root identifier */
    public void setFamilyId(String familyId) {
        this.familyId = familyId;
    }

    /** @return the replaced generation identifier, {@code null} on the root */
    public String getParentId() {
        return parentId;
    }

    /** @param parentId the replaced generation identifier */
    public void setParentId(String parentId) {
        this.parentId = parentId;
    }

    /** @return the stored hash */
    public String getTokenHash() {
        return tokenHash;
    }

    /** @param tokenHash the stored hash */
    public void setTokenHash(String tokenHash) {
        this.tokenHash = tokenHash;
    }

    /** @return the lifecycle status */
    public RefreshTokenStatus getStatus() {
        return status;
    }

    /** @param status the lifecycle status */
    public void setStatus(RefreshTokenStatus status) {
        this.status = status;
    }

    /** @return expiry instant */
    public Instant getExpiresAt() {
        return expiresAt;
    }

    /** @param expiresAt expiry instant */
    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    /** @return rotation instant, {@code null} unless rotated */
    public Instant getRotatedAt() {
        return rotatedAt;
    }

    /** @param rotatedAt rotation instant */
    public void setRotatedAt(Instant rotatedAt) {
        this.rotatedAt = rotatedAt;
    }

    /** @return revocation instant, {@code null} unless revoked */
    public Instant getRevokedAt() {
        return revokedAt;
    }

    /** @param revokedAt revocation instant */
    public void setRevokedAt(Instant revokedAt) {
        this.revokedAt = revokedAt;
    }

    /** @return revocation reason, {@code null} unless revoked */
    public RevocationReason getRevokedReason() {
        return revokedReason;
    }

    /** @param revokedReason revocation reason */
    public void setRevokedReason(RevocationReason revokedReason) {
        this.revokedReason = revokedReason;
    }

}
