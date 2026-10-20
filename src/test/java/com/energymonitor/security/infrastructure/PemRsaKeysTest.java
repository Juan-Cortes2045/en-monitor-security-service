package com.energymonitor.security.infrastructure;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.result.AuthenticatedUser;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.UserStatus;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * Which PEM files {@link JwtConfiguration} accepts, and what it says when it refuses one.
 *
 * <p>There is no way to choose a format in the configuration, so the reader has to recognise
 * whatever OpenSSL produced: {@code genpkey} writes PKCS#8 while {@code genrsa} writes PKCS#1,
 * and the same split exists on the public side. A deployment that followed either instruction
 * must start.
 */
class PemRsaKeysTest {

    private static final String ISSUER = "https://energy-monitor-backend";
    private static final Duration TTL = Duration.ofMinutes(15);

    private static KeyPair keyPair;

    @TempDir
    Path tempDir;

    @BeforeAll
    static void generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    // ------------------------------------------------------------------ PKCS#8 and X.509

    @Test
    void readsAPkcs8PrivateKey() {
        Path path = write("pkcs8_private.pem", "PRIVATE KEY", keyPair.getPrivate().getEncoded());

        RSAPrivateKey key = PemRsaKeys.readPrivateKey(path);

        assertEquals(((RSAPrivateCrtKey) keyPair.getPrivate()).getModulus(), key.getModulus());
    }

    @Test
    void readsAnX509PublicKey() {
        Path path = write("x509_public.pem", "PUBLIC KEY", keyPair.getPublic().getEncoded());

        RSAPublicKey key = PemRsaKeys.readPublicKey(path);

        assertEquals(keyPair.getPublic(), key);
    }

    // ------------------------------------------------------------------ PKCS#1

    @Test
    void readsAPkcs1PrivateKey() {
        Path path = write("pkcs1_private.pem", "RSA PRIVATE KEY", pkcs1((RSAPrivateCrtKey) keyPair.getPrivate()));

        RSAPrivateKey key = PemRsaKeys.readPrivateKey(path);

        RSAPrivateCrtKey expected = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPrivateCrtKey actual = (RSAPrivateCrtKey) key;
        assertEquals(expected.getModulus(), actual.getModulus());
        assertEquals(expected.getPublicExponent(), actual.getPublicExponent());
        assertEquals(expected.getPrivateExponent(), actual.getPrivateExponent());
        assertEquals(expected.getPrimeP(), actual.getPrimeP());
        assertEquals(expected.getPrimeQ(), actual.getPrimeQ());
        assertEquals(expected.getPrimeExponentP(), actual.getPrimeExponentP());
        assertEquals(expected.getPrimeExponentQ(), actual.getPrimeExponentQ());
        assertEquals(expected.getCrtCoefficient(), actual.getCrtCoefficient());
    }

    @Test
    void readsAPkcs1PublicKey() {
        RSAPublicKey expected = (RSAPublicKey) keyPair.getPublic();
        Path path = write("pkcs1_public.pem", "RSA PUBLIC KEY",
                sequence(integer(expected.getModulus()), integer(expected.getPublicExponent())));

        assertEquals(expected, PemRsaKeys.readPublicKey(path));
    }

    /**
     * The end-to-end claim: a pair in PKCS#1 form signs a token that the X.509 public key the
     * decoder reads accepts. Both files coming from OpenSSL is the deployment this supports.
     */
    @Test
    void signsWithAPkcs1PrivateKeyAndVerifiesWithThePublicKey() {
        Path privateKey = write("pair_pkcs1_private.pem", "RSA PRIVATE KEY",
                pkcs1((RSAPrivateCrtKey) keyPair.getPrivate()));
        Path publicKey = write("pair_x509_public.pem", "PUBLIC KEY", keyPair.getPublic().getEncoded());

        JwtConfiguration configuration = new JwtConfiguration();
        SecurityJwtProperties properties =
                new SecurityJwtProperties(ISSUER, TTL, privateKey.toString(), publicKey.toString());
        JwtDecoder decoder = configuration.jwtDecoder(properties);
        String token = new JwtTokenIssuer(configuration.jwtEncoder(properties), properties,
                Clock.system(ZoneOffset.UTC))
                .issue(new AuthenticatedUser("USR0000001", "PER0000001",
                        Email.of("someone@example.com"), UserStatus.ACTIVE, Instant.now(), null));

        assertEquals("USR0000001", decoder.decode(token).getSubject());
    }

    // ------------------------------------------------------------------ whitespace

    @Test
    void readsAPemWithWindowsLineEndings() {
        Path path = writeRaw("crlf_private.pem", "PRIVATE KEY", keyPair.getPrivate().getEncoded(),
                "\r\n");

        assertNotNull(PemRsaKeys.readPrivateKey(path));
    }

    @Test
    void readsAPemWhoseLinesCarryTrailingSpacesAndTabs() {
        String base64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        Path path = write("tabbed_private.pem", "-----BEGIN PRIVATE KEY-----\n\t" + base64
                + "\t \n-----END PRIVATE KEY-----\t\n");

        assertNotNull(PemRsaKeys.readPrivateKey(path));
    }

    @Test
    void readsABareBase64BodyWithNoHeaderAtAll() {
        Path path = write("bare_private.pem",
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));

        assertEquals(((RSAPrivateCrtKey) keyPair.getPrivate()).getModulus(),
                PemRsaKeys.readPrivateKey(path).getModulus());
    }

    @Test
    void readsAPrivateKeyWhoseHeaderIsLowerCase() {
        Path path = write("lower_private.pem", "private key", keyPair.getPrivate().getEncoded());

        assertNotNull(PemRsaKeys.readPrivateKey(path));
    }

    // ------------------------------------------------------------------ refusals

    @Test
    void refusesAnEncryptedPrivateKeyByName() throws IOException {
        Path path = Files.writeString(tempDir.resolve("encrypted.pem"),
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n");

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> PemRsaKeys.readPrivateKey(path));

        assertTrue(failure.getMessage().contains("passphrase"), failure.getMessage());
    }

    @Test
    void refusesAPublicKeyOfferedAsThePrivateOne() {
        Path path = write("wrong_private.pem", "PUBLIC KEY", keyPair.getPublic().getEncoded());

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> PemRsaKeys.readPrivateKey(path));

        assertTrue(failure.getMessage().contains("public key"), failure.getMessage());
    }

    @Test
    void refusesAPrivateKeyOfferedAsThePublicOne() {
        Path path = write("wrong_public.pem", "PRIVATE KEY", keyPair.getPrivate().getEncoded());

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> PemRsaKeys.readPublicKey(path));

        assertTrue(failure.getMessage().contains("private key"), failure.getMessage());
    }

    @Test
    void refusesAnUnknownPemLabel() throws IOException {
        Path path = Files.writeString(tempDir.resolve("odd.pem"),
                "-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----\n");

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> PemRsaKeys.readPrivateKey(path));

        assertTrue(failure.getMessage().contains("DSA PRIVATE KEY"), failure.getMessage());
    }

    @Test
    void refusesAPemWithNoKeyMaterial() throws IOException {
        Path path = Files.writeString(tempDir.resolve("empty.pem"),
                "-----BEGIN PRIVATE KEY-----\n\r\n-----END PRIVATE KEY-----\n");

        assertThrows(IllegalStateException.class, () -> PemRsaKeys.readPrivateKey(path));
    }

    @Test
    void refusesGarbageThatIsNotBase64() throws IOException {
        Path path = Files.writeString(tempDir.resolve("garbage.pem"),
                "-----BEGIN PRIVATE KEY-----\nINVALID\n-----END PRIVATE KEY-----\n");

        assertThrows(IllegalStateException.class, () -> PemRsaKeys.readPrivateKey(path));
    }

    @Test
    void refusesAMissingFileByPath() {
        Path path = tempDir.resolve("absent.pem");

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> PemRsaKeys.readPrivateKey(path));

        assertTrue(failure.getMessage().contains("absent.pem"), failure.getMessage());
    }

    @Test
    void namesTheEnvironmentVariableWhenNoPrivateKeyPathIsConfigured() {
        SecurityJwtProperties missing = new SecurityJwtProperties(ISSUER, TTL,
                "  ", write("pkcs8_private.pem", "PRIVATE KEY", keyPair.getPrivate().getEncoded())
                        .toString());

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> new JwtConfiguration().jwtEncoder(missing));

        assertTrue(failure.getMessage().contains("SECURITY_JWT_PRIVATE_KEY_PATH"),
                failure.getMessage());
        assertTrue(failure.getMessage().contains("openssl genpkey"), failure.getMessage());
    }

    @Test
    void namesTheEnvironmentVariableWhenNoPublicKeyPathIsConfigured() {
        SecurityJwtProperties missing = new SecurityJwtProperties(ISSUER, TTL,
                write("pkcs8_private.pem", "PRIVATE KEY", keyPair.getPrivate().getEncoded())
                        .toString(), null);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> new JwtConfiguration().jwtDecoder(missing));

        assertTrue(failure.getMessage().contains("SECURITY_JWT_PUBLIC_KEY_PATH"),
                failure.getMessage());
    }

    @Test
    void toleratesSurroundingWhitespaceInTheConfiguredPath() {
        Path path = write("spaced_private.pem", "PRIVATE KEY", keyPair.getPrivate().getEncoded());
        Path publicKey = write("spaced_public.pem", "PUBLIC KEY", keyPair.getPublic().getEncoded());
        SecurityJwtProperties properties = new SecurityJwtProperties(ISSUER, TTL,
                "  " + path + "  ", publicKey.toString());

        assertNotNull(new JwtConfiguration().jwtEncoder(properties));
    }

    // ------------------------------------------------------------------ fixtures

    private Path write(String name, String label, byte[] encoded) {
        return writeRaw(name, label, encoded, "\n");
    }

    private Path writeRaw(String name, String label, byte[] encoded, String newline) {
        String base64 = Base64.getEncoder().encodeToString(encoded);
        StringBuilder pem = new StringBuilder("-----BEGIN ").append(label).append("-----").append(newline);
        for (int i = 0; i < base64.length(); i += 64) {
            pem.append(base64, i, Math.min(i + 64, base64.length())).append(newline);
        }
        pem.append("-----END ").append(label).append("-----").append(newline);
        return write(name, pem.toString());
    }

    private Path write(String name, String contents) {
        try {
            return Files.writeString(tempDir.resolve(name), contents, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * The PKCS#1 RSAPrivateKey sequence, which is what an {@code RSA PRIVATE KEY} PEM holds
     * and what no Java {@code KeySpec} reads directly.
     */
    private static byte[] pkcs1(RSAPrivateCrtKey key) {
        return sequence(
                integer(BigInteger.ZERO),
                integer(key.getModulus()),
                integer(key.getPublicExponent()),
                integer(key.getPrivateExponent()),
                integer(key.getPrimeP()),
                integer(key.getPrimeQ()),
                integer(key.getPrimeExponentP()),
                integer(key.getPrimeExponentQ()),
                integer(key.getCrtCoefficient()));
    }

    private static byte[] sequence(byte[]... values) {
        return tagged(0x30, concat(values));
    }

    private static byte[] integer(BigInteger value) {
        byte[] magnitude = value.toByteArray();
        if (magnitude.length > 1 && magnitude[0] == 0) {
            byte[] trimmed = new byte[magnitude.length - 1];
            System.arraycopy(magnitude, 1, trimmed, 0, trimmed.length);
            magnitude = trimmed;
        }
        return tagged(0x02, magnitude);
    }

    private static byte[] tagged(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (content.length < 0x80) {
            out.write(content.length);
        } else if (content.length < 0x100) {
            out.write(0x81);
            out.write(content.length);
        } else {
            out.write(0x82);
            out.write(content.length >>> 8);
            out.write(content.length);
        }
        out.writeBytes(content);
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... values) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] value : values) {
            out.writeBytes(value);
        }
        return out.toByteArray();
    }
}
