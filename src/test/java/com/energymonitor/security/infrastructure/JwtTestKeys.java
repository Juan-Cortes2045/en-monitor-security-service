package com.energymonitor.security.infrastructure;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * The RSA key pair every Spring context in this test suite signs and validates with.
 *
 * <p>Generated per test JVM rather than checked in: a versioned private key is a leaked private
 * key, and a key copied between environments is a key nobody remembers to rotate. The files land
 * in a temporary directory and are removed when the JVM exits, so the same names never mean the
 * same key twice.
 *
 * <p>The files are written in the two formats {@code openssl genpkey} and
 * {@code openssl rsa -pubout} produce - PKCS#8 and X.509 SubjectPublicKeyInfo - which is the
 * reason a suite-wide context needs no per-class PEM writing.
 */
public final class JwtTestKeys {

    /** Matches the issuer in {@code application.yaml}, so the tests exercise the real value. */
    public static final String ISSUER = "https://energy-monitor-backend";

    /** Matches the default lifetime in {@code application.yaml}. */
    public static final String ACCESS_TOKEN_TTL = "15m";

    private static final int KEY_SIZE = 2048;
    private static final int PEM_LINE_LENGTH = 64;

    private JwtTestKeys() {
    }

    /**
     * Generates the pair and writes it as two PEM files.
     *
     * @return the key pair with the paths of its files
     */
    public static Keys generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(KEY_SIZE);
            KeyPair keyPair = generator.generateKeyPair();

            Path directory = Files.createTempDirectory("energy-monitor-jwt");
            // deleteOnExit runs in reverse registration order, so the directory is registered
            // first and emptied after the two files inside it are gone.
            directory.toFile().deleteOnExit();

            Path privateKey = directory.resolve("private.pem");
            Path publicKey = directory.resolve("public.pem");
            write(privateKey, keyPair.getPrivate().getEncoded(), "PRIVATE KEY");
            write(publicKey, keyPair.getPublic().getEncoded(), "PUBLIC KEY");

            return new Keys(keyPair, privateKey, publicKey);
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not generate an RSA key pair for the tests", e);
        }
    }

    private static void write(Path path, byte[] encoded, String label) throws IOException {
        String base64 = Base64.getEncoder().encodeToString(encoded);
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN ").append(label).append("-----\n");
        for (int i = 0; i < base64.length(); i += PEM_LINE_LENGTH) {
            pem.append(base64, i, Math.min(i + PEM_LINE_LENGTH, base64.length())).append('\n');
        }
        pem.append("-----END ").append(label).append("-----\n");
        Files.writeString(path, pem.toString(), StandardCharsets.UTF_8);
        path.toFile().deleteOnExit();
    }

    /**
     * A generated key pair and the PEM files holding it.
     *
     * @param keyPair   the pair itself, for a test that has to verify a token itself
     * @param privateKey path of the PKCS#8 private key
     * @param publicKey  path of the X.509 public key
     */
    public record Keys(KeyPair keyPair, Path privateKey, Path publicKey) {
    }
}
