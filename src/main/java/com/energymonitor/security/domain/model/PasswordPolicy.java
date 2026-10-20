package com.energymonitor.security.domain.model;

import java.util.Objects;

/**
 * Rules a password must satisfy before the system accepts it.
 *
 * <p>Applies both at registration and at reset time (INV-016). The domain only checks the
 * shape of a candidate password; hashing and persistence belong to the security adapter.
 *
 * <p>Maps to the {@code password_policy} table.
 */
public class PasswordPolicy {

    private final String idPasswordPolicy;
    private final int minLength;
    private final int maxLength;
    private final boolean requireUppercase;
    private final boolean requireNumbers;
    private final boolean requireSymbols;
    private final int expirationDays;

    /**
     * @param idPasswordPolicy identifier, {@code VARCHAR(10)}
     * @param minLength        minimum accepted length, greater than zero
     * @param maxLength        maximum accepted length, not below {@code minLength}
     * @param requireUppercase whether an upper-case letter is required
     * @param requireNumbers   whether a digit is required
     * @param requireSymbols   whether a symbol is required
     * @param expirationDays   days a password stays valid, greater than zero
     * @throws IllegalStateException if the length bounds are inconsistent
     */
    public PasswordPolicy(String idPasswordPolicy, int minLength, int maxLength,
                          boolean requireUppercase, boolean requireNumbers,
                          boolean requireSymbols, int expirationDays) {
        this.idPasswordPolicy = Preconditions.text(idPasswordPolicy, "idPasswordPolicy");
        this.minLength = Preconditions.positive(minLength, "minLength");
        this.maxLength = Preconditions.positive(maxLength, "maxLength");
        if (maxLength < minLength) {
            throw new IllegalStateException("maxLength must be greater than or equal to minLength");
        }
        this.requireUppercase = requireUppercase;
        this.requireNumbers = requireNumbers;
        this.requireSymbols = requireSymbols;
        this.expirationDays = Preconditions.positive(expirationDays, "expirationDays");
    }

    /** @return the identifier */
    public String idPasswordPolicy() {
        return idPasswordPolicy;
    }

    /** @return minimum accepted length */
    public int minLength() {
        return minLength;
    }

    /** @return maximum accepted length */
    public int maxLength() {
        return maxLength;
    }

    /** @return whether an upper-case letter is required */
    public boolean requiresUppercase() {
        return requireUppercase;
    }

    /** @return whether a digit is required */
    public boolean requiresNumbers() {
        return requireNumbers;
    }

    /** @return whether a symbol is required */
    public boolean requiresSymbols() {
        return requireSymbols;
    }

    /** @return password validity in days */
    public int expirationDays() {
        return expirationDays;
    }

    /**
     * Whether a candidate password satisfies this policy (INV-015).
     *
     * <p>Purely a shape check: it does not know whether the password was ever used before,
     * and it never hashes.
     *
     * @param rawPassword the candidate; {@code null} or blank always fails
     * @return {@code true} when every active rule is met
     */
    public boolean isSatisfiedBy(String rawPassword) {
        if (rawPassword == null || rawPassword.isEmpty()) {
            return false;
        }
        if (rawPassword.length() < minLength || rawPassword.length() > maxLength) {
            return false;
        }
        if (requireUppercase && rawPassword.chars().noneMatch(Character::isUpperCase)) {
            return false;
        }
        if (requireNumbers && rawPassword.chars().noneMatch(Character::isDigit)) {
            return false;
        }
        if (requireSymbols && rawPassword.chars().allMatch(Character::isLetterOrDigit)) {
            return false;
        }
        return true;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof PasswordPolicy that)) {
            return false;
        }
        return idPasswordPolicy.equals(that.idPasswordPolicy);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idPasswordPolicy);
    }

    @Override
    public String toString() {
        return "PasswordPolicy{idPasswordPolicy='" + idPasswordPolicy + "', minLength=" + minLength
                + ", maxLength=" + maxLength + "}";
    }
}
