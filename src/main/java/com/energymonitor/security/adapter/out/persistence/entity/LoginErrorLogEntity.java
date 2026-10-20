package com.energymonitor.security.adapter.out.persistence.entity;

import com.energymonitor.security.domain.model.LoginErrorType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * JPA mapping of the {@code login_error_log} table.
 *
 * <p>{@code user_id} is nullable because the attempt may not have matched any account. The
 * domain rehydration constructor accepts that, and only for
 * {@code LoginErrorType.USER_NOT_FOUND}.
 *
 * <p>The domain's {@code occurredAt} is stored in {@code created_at}: the column is the only
 * timestamp a failed attempt has, and it carries the event time.
 */
@Entity
@Table(name = "login_error_log")
public class LoginErrorLogEntity extends BaseAuditEntity {

    @Id
    @Column(name = "id_login_error", nullable = false, length = 10)
    private String idLoginError;

    @Column(name = "user_id", length = 10)
    private String userId;

    @Enumerated(EnumType.STRING)
    @Column(name = "error_type", nullable = false)
    private LoginErrorType errorType;

    @Column(name = "description", length = 500)
    private String description;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    public LoginErrorLogEntity() {
    }

    public String getIdLoginError() {
        return idLoginError;
    }

    public void setIdLoginError(String idLoginError) {
        this.idLoginError = idLoginError;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public LoginErrorType getErrorType() {
        return errorType;
    }

    public void setErrorType(LoginErrorType errorType) {
        this.errorType = errorType;
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
}
