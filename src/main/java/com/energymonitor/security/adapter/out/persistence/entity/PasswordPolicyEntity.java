package com.energymonitor.security.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * JPA mapping of the {@code password_policy} table.
 *
 * <p>The three requirement switches map to MySQL {@code tinyint(1)} columns, which the JDBC
 * driver reports as a single-bit type, so {@code boolean} is the faithful Java counterpart.
 */
@Entity
@Table(name = "password_policy")
public class PasswordPolicyEntity extends BaseAuditEntity {

    @Id
    @Column(name = "id_password_policy", nullable = false, length = 10)
    private String idPasswordPolicy;

    @Column(name = "min_length", nullable = false)
    private int minLength;

    @Column(name = "max_length", nullable = false)
    private int maxLength;

    @Column(name = "require_uppercase", nullable = false)
    @TinyIntBoolean
    private boolean requireUppercase;

    @Column(name = "require_numbers", nullable = false)
    @TinyIntBoolean
    private boolean requireNumbers;

    @Column(name = "require_symbols", nullable = false)
    @TinyIntBoolean
    private boolean requireSymbols;

    @Column(name = "expiration_days", nullable = false)
    private int expirationDays;

    public PasswordPolicyEntity() {
    }

    public String getIdPasswordPolicy() {
        return idPasswordPolicy;
    }

    public void setIdPasswordPolicy(String idPasswordPolicy) {
        this.idPasswordPolicy = idPasswordPolicy;
    }

    public int getMinLength() {
        return minLength;
    }

    public void setMinLength(int minLength) {
        this.minLength = minLength;
    }

    public int getMaxLength() {
        return maxLength;
    }

    public void setMaxLength(int maxLength) {
        this.maxLength = maxLength;
    }

    public boolean isRequireUppercase() {
        return requireUppercase;
    }

    public void setRequireUppercase(boolean requireUppercase) {
        this.requireUppercase = requireUppercase;
    }

    public boolean isRequireNumbers() {
        return requireNumbers;
    }

    public void setRequireNumbers(boolean requireNumbers) {
        this.requireNumbers = requireNumbers;
    }

    public boolean isRequireSymbols() {
        return requireSymbols;
    }

    public void setRequireSymbols(boolean requireSymbols) {
        this.requireSymbols = requireSymbols;
    }

    public int getExpirationDays() {
        return expirationDays;
    }

    public void setExpirationDays(int expirationDays) {
        this.expirationDays = expirationDays;
    }
}
