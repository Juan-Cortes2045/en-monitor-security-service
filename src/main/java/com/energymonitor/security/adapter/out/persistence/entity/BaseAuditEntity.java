package com.energymonitor.security.adapter.out.persistence.entity;

import com.energymonitor.security.adapter.out.persistence.support.Instants;
import jakarta.persistence.Column;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import java.time.Instant;

/**
 * Technical audit columns shared by every Security table.
 *
 * <p>These three columns are infrastructure, not business state: the domain deliberately has
 * no counterpart for them, so mappers ignore them. They live in one place here instead of
 * being repeated thirteen times.
 *
 * <p><strong>Why the application writes them.</strong> The schema also carries
 * {@code DEFAULT CURRENT_TIMESTAMP} and {@code ON UPDATE CURRENT_TIMESTAMP}. The application
 * stamps them instead, in {@link #onPersist()} and {@link #onUpdate()}, for two reasons:
 * leaving them to the database would require marking the columns {@code insertable = false},
 * and a single mechanism is easier to reason about than a mix of database defaults and
 * application defaults. The value written is still whole seconds and still UTC, so both
 * strategies produce the same shape of data.
 *
 * <p>Subclasses may preset {@code createdAt} before persisting. That is how the business
 * event time of {@code audit_log} and {@code login_error_log} is written into the
 * {@code created_at} column, and the callback leaves a non-null value untouched.
 */
@MappedSuperclass
public abstract class BaseAuditEntity {

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    /**
     * Stamps the audit columns on insert, unless a subclass already decided the creation time.
     */
    @PrePersist
    void onPersist() {
        Instant now = Instants.now();
        if (createdAt == null) {
            createdAt = now;
        }
        updatedAt = now;
    }

    /** Stamps {@code updated_at} on every update. */
    @PreUpdate
    void onUpdate() {
        updatedAt = Instants.now();
    }

    /** @return creation instant, the business event time for the immutable logs */
    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    /** @return last modification instant */
    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    /** @return soft-deletion instant, {@code null} while the row is active */
    public Instant getDeletedAt() {
        return deletedAt;
    }

    public void setDeletedAt(Instant deletedAt) {
        this.deletedAt = deletedAt;
    }

    /** @return whether the row has been soft-deleted */
    public boolean isSoftDeleted() {
        return deletedAt != null;
    }
}
