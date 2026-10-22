package com.energymonitor.security.domain.model;

import java.util.Objects;
import java.util.Optional;

/**
 * Personal preferences of a single {@link User}.
 *
 * <p>Notification switches are primitive booleans, never nullable, because a preference must
 * always be an explicit decision (INV-008). The one-to-one link with the user is enforced by
 * {@code uk_user_configuration_user_id} (INV-007).
 *
 * <p>Maps to the {@code user_configuration} table.
 */
public class UserConfiguration {

    private static final int THEME_MAX = 50;
    private static final int LANGUAGE_MAX = 50;
    private static final int PROVIDER_MAX = 50;

    private final String idConfiguration;
    private final String idUser;
    private boolean notifyByEmail;
    private boolean notifyByPush;
    private String colorTheme;
    private String language;
    private String socialProvider;

    /**
     * @param idConfiguration identifier, {@code VARCHAR(10)}
     * @param idUser          owning user
     * @param notifyByEmail   email notifications on
     * @param notifyByPush    push notifications on
     * @param colorTheme      optional theme
     * @param language        optional language
     * @param socialProvider  optional social login provider
     */
    public UserConfiguration(String idConfiguration, String idUser, boolean notifyByEmail,
                             boolean notifyByPush, String colorTheme, String language,
                             String socialProvider) {
        this.idConfiguration = Preconditions.text(idConfiguration, "idConfiguration");
        this.idUser = Preconditions.text(idUser, "idUser");
        this.notifyByEmail = notifyByEmail;
        this.notifyByPush = notifyByPush;
        this.colorTheme = Preconditions.optionalText(colorTheme, THEME_MAX, "colorTheme");
        this.language = Preconditions.optionalText(language, LANGUAGE_MAX, "language");
        this.socialProvider = Preconditions.optionalText(socialProvider, PROVIDER_MAX, "socialProvider");
    }

    /**
     * Creates a configuration with notifications on and no customisation.
     *
     * @param idConfiguration identifier
     * @param idUser          owning user
     * @return the default configuration
     */
    public static UserConfiguration withDefaults(String idConfiguration, String idUser) {
        return new UserConfiguration(idConfiguration, idUser, true, true, null, null, null);
    }

    /** @return the identifier */
    public String idConfiguration() {
        return idConfiguration;
    }

    /** @return owning user identifier */
    public String idUser() {
        return idUser;
    }

    /** @return whether email notifications are enabled */
    public boolean notifyByEmail() {
        return notifyByEmail;
    }

    /** @return whether push notifications are enabled */
    public boolean notifyByPush() {
        return notifyByPush;
    }

    /** @return theme, empty when not set */
    public Optional<String> colorTheme() {
        return Optional.ofNullable(colorTheme);
    }

    /** @return language, empty when not set */
    public Optional<String> language() {
        return Optional.ofNullable(language);
    }

    /** @return social login provider, empty when the account is not linked to one */
    public Optional<String> socialProvider() {
        return Optional.ofNullable(socialProvider);
    }

    /** @return whether at least one notification channel is on */
    public boolean hasAnyNotificationChannel() {
        return notifyByEmail || notifyByPush;
    }

    /** Turns email notifications on or off. */
    public void setNotifyByEmail(boolean notifyByEmail) {
        this.notifyByEmail = notifyByEmail;
    }

    /** Turns push notifications on or off. */
    public void setNotifyByPush(boolean notifyByPush) {
        this.notifyByPush = notifyByPush;
    }

    /**
     * Sets the colour theme. Passing {@code null} clears it.
     *
     * @param colorTheme new theme or {@code null}
     */
    public void changeColorTheme(String colorTheme) {
        this.colorTheme = Preconditions.optionalText(colorTheme, THEME_MAX, "colorTheme");
    }

    /**
     * Sets the preferred language. Passing {@code null} clears it.
     *
     * @param language new language or {@code null}
     */
    public void changeLanguage(String language) {
        this.language = Preconditions.optionalText(language, LANGUAGE_MAX, "language");
    }

    /**
     * Links the account to a social login provider. Passing {@code null} unlinks it.
     *
     * @param socialProvider provider name or {@code null}
     */
    public void linkSocialProvider(String socialProvider) {
        this.socialProvider = Preconditions.optionalText(socialProvider, PROVIDER_MAX, "socialProvider");
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof UserConfiguration that)) {
            return false;
        }
        return idConfiguration.equals(that.idConfiguration);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idConfiguration);
    }

    @Override
    public String toString() {
        return "UserConfiguration{idConfiguration='" + idConfiguration + "', idUser='" + idUser + "'}";
    }
}
