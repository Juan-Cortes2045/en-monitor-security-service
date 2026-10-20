package com.energymonitor.security.application.port.out;

/**
 * Output port for turning a refresh token secret into its stored form.
 *
 * <p>Abstracted so the domain never sees a digest function, and so the algorithm is a
 * deployment decision rather than something baked into the model. The application uses it in
 * exactly two places: hashing a freshly generated secret before storing it, and hashing a
 * presented secret to resolve which generation it is.
 */
public interface RefreshTokenHasherPort {

    /**
     * Hashes a secret for storage.
     *
     * <p>The result is what the database holds. The secret itself is not retained anywhere and
     * is handed to the client only by the flow that generated it.
     *
     * @param rawToken the secret, in clear text
     * @return the stored representation of the secret
     * @throws IllegalArgumentException if the secret is null or blank
     */
    String hash(String rawToken);
}
