package com.energymonitor.security.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * JPA mapping of the {@code password_reset_token} table.
 *
 * <p>There is deliberately no field for the clear secret: only {@code reset_token_hash} is
 * mapped, so the mapping offers no way to persist a redeemable credential even if a caller
 * handed one over. The domain holds that value in memory for delivery and the entity never sees
 * it.
 *
 * <p>{@code used} is stored as a real column and never inferred. Rehydration has to hand the
 * domain the flag exactly as persisted, otherwise a consumed token would come back looking
 * fresh and could be redeemed twice.
 */
@Entity
@Table(name = "password_reset_token")
public class PasswordResetTokenEntity extends BaseAuditEntity {

    @Id
    @Column(name = "id_reset_token", nullable = false, length = 10)
    private String idResetToken;

    @Column(name = "user_id", nullable = false, length = 10)
    private String userId;

    /** Lowercase hex SHA-256: 32 bytes rendered as 64 characters. */
    @Column(name = "reset_token_hash", nullable = false, length = 64)
    private String resetTokenHash;

    @Column(name = "used", nullable = false)
    @TinyIntBoolean
    private boolean used;

    /**
     * Redemption attempts already reserved for this code, spent by a conditional update.
     *
     * <p>A plain column rather than anything derived, because under concurrency the value the
     * database increments is the authoritative one and this field is only a read of it.
     *
     * <p>No {@link TinyIntBoolean} here, unlike {@code used}: the flag stores a boolean, this
     * stores a count, and a counter capped at five must not be squeezed into a single boolean
     * column by a mapping convention meant for flags.
     */
    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "expiration_at", nullable = false)
    private Instant expirationAt;

    public PasswordResetTokenEntity() {
    }

    public String getIdResetToken() {
        return idResetToken;
    }

    public void setIdResetToken(String idResetToken) {
        this.idResetToken = idResetToken;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getResetTokenHash() {
        return resetTokenHash;
    }

    public void setResetTokenHash(String resetTokenHash) {
        this.resetTokenHash = resetTokenHash;
    }

    public boolean isUsed() {
        return used;
    }

    public void setUsed(boolean used) {
        this.used = used;
    }

    /** @return attempts already reserved against this code */
    public int getAttempts() {
        return attempts;
    }

    public void setAttempts(int attempts) {
        this.attempts = attempts;
    }

    /** @return expiry instant, read from the column named in the changelog */
    public Instant getExpirationAt() {
        return expirationAt;
    }

    public void setExpirationAt(Instant expirationAt) {
        this.expirationAt = expirationAt;
    }
}
