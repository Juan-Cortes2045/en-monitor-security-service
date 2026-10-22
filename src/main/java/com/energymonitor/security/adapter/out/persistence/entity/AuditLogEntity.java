package com.energymonitor.security.adapter.out.persistence.entity;

import com.energymonitor.security.domain.model.AuditAction;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * JPA mapping of the {@code audit_log} table.
 *
 * <p>Immutable by contract, so this entity exposes setters only because JPA requires them;
 * the adapter never edits an existing audit row.
 *
 * <p>The domain's {@code occurredAt} is written to {@code created_at}, which is the only
 * column carrying the event time.
 */
@Entity
@Table(name = "audit_log")
public class AuditLogEntity extends BaseAuditEntity {

    @Id
    @Column(name = "id_audit_log", nullable = false, length = 10)
    private String idAuditLog;

    @Column(name = "user_id", length = 10)
    private String userId;

    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false)
    private AuditAction action;

    @Column(name = "description", length = 255)
    private String description;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "application", length = 255)
    private String application;

    public AuditLogEntity() {
    }

    public String getIdAuditLog() {
        return idAuditLog;
    }

    public void setIdAuditLog(String idAuditLog) {
        this.idAuditLog = idAuditLog;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public AuditAction getAction() {
        return action;
    }

    public void setAction(AuditAction action) {
        this.action = action;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getApplication() {
        return application;
    }

    public void setApplication(String application) {
        this.application = application;
    }
}
