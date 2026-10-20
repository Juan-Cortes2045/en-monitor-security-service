package com.energymonitor.security.adapter.out.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * JPA mapping of the {@code user_configuration} table.
 *
 * <p>The unique constraint on {@code user_id} is not restated here: it is already declared by
 * changeset {@code security-003} as {@code uk_user_configuration_user_id}, and
 * {@code ddl-auto=validate} checks the mapping against the live schema rather than against a
 * generated one.
 */
@Entity
@Table(name = "user_configuration")
public class UserConfigurationEntity extends BaseAuditEntity {

    @Id
    @Column(name = "id_configuration", nullable = false, length = 10)
    private String idConfiguration;

    @Column(name = "user_id", nullable = false, length = 10)
    private String userId;

    @Column(name = "notify_by_email", nullable = false)
    @TinyIntBoolean
    private boolean notifyByEmail;

    @Column(name = "notify_by_push", nullable = false)
    @TinyIntBoolean
    private boolean notifyByPush;

    @Column(name = "color_theme", length = 50)
    private String colorTheme;

    @Column(name = "language", length = 50)
    private String language;

    @Column(name = "social_provider", length = 50)
    private String socialProvider;

    public UserConfigurationEntity() {
    }

    public String getIdConfiguration() {
        return idConfiguration;
    }

    public void setIdConfiguration(String idConfiguration) {
        this.idConfiguration = idConfiguration;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public boolean isNotifyByEmail() {
        return notifyByEmail;
    }

    public void setNotifyByEmail(boolean notifyByEmail) {
        this.notifyByEmail = notifyByEmail;
    }

    public boolean isNotifyByPush() {
        return notifyByPush;
    }

    public void setNotifyByPush(boolean notifyByPush) {
        this.notifyByPush = notifyByPush;
    }

    public String getColorTheme() {
        return colorTheme;
    }

    public void setColorTheme(String colorTheme) {
        this.colorTheme = colorTheme;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public String getSocialProvider() {
        return socialProvider;
    }

    public void setSocialProvider(String socialProvider) {
        this.socialProvider = socialProvider;
    }
}
