package com.energymonitor.security.application.port.out;

/**
 * Output port for turning a password-recovery code into its stored form.
 *
 * <p>Separate from {@link RefreshTokenHasherPort} even though the two are served by different
 * adapters: each port names the credential it exists for, so a use case never has to be read
 * against a port whose subject is a different token.
 *
 * <p><strong>The account is part of what is hashed.</strong> That is what ties a code to the user
 * it was issued to, and it is not decoration: a six-digit code is a small space, so a digest of
 * the code alone is the same value for every account, and whoever guessed a code that happened to
 * be live could redeem it against the row that hash resolved to. Binding the identifier means a
 * presented code is only ever comparable against the token of the account it was requested for.
 *
 * <p>Nothing about the digest belongs to the application layer, which uses this port in exactly
 * two places: hashing a freshly generated code before it is stored, and hashing a presented code
 * to compare it with the stored one.
 */
public interface PasswordResetTokenHasherPort {

    /**
     * Hashes a recovery code for one account.
     *
     * <p>What the database holds is the result of this call. The code itself is not retained and
     * is handed to the account owner only by the flow that generated it.
     *
     * @param idUser    the account the code was issued to, which is part of the hashed material
     * @param clearCode the code, in clear text
     * @return the stored representation, comparable only against a code of the same account
     * @throws IllegalArgumentException if the identifier or the code is null or blank
     */
    String hash(String idUser, String clearCode);
}