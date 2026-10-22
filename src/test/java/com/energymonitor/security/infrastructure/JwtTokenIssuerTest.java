package com.energymonitor.security.infrastructure;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.energymonitor.security.application.result.AuthenticatedUser;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.UserStatus;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Behaviour of the JWT issuer and of the encoder/decoder pair it is built on.
 */
class JwtTokenIssuerTest {

    private static final String ISSUER = "https://energy-monitor-backend";
    private static final Duration TTL = Duration.ofMinutes(15);
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);

    @TempDir
    Path tempDir;

    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private Path privateKeyPath;
    private Path publicKeyPath;
    private KeyPair keyPair;
    private JwtTokenIssuer issuer;

    @BeforeEach
    void setUp() throws Exception {
        keyPair = generateRsaKeyPair();
        privateKeyPath = tempDir.resolve("private.pem");
        publicKeyPath = tempDir.resolve("public.pem");
        writePemPrivateKey(privateKeyPath, keyPair);
        writePemPublicKey(publicKeyPath, keyPair);

        SecurityJwtProperties properties = new SecurityJwtProperties(ISSUER, TTL,
                privateKeyPath.toString(), publicKeyPath.toString());
        JwtConfiguration configuration = new JwtConfiguration();
        issuer = new JwtTokenIssuer(configuration.jwtEncoder(properties), properties, clock);
    }

    private static AuthenticatedUser identity() {
        return new AuthenticatedUser("USR0000001", "PER0000001",
                Email.of("someone@example.com"), UserStatus.ACTIVE, NOW, null);
    }

    private Jwt decode(String token) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic())
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(ISSUER));
        return decoder.decode(token);
    }

    private static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private void writePemPrivateKey(Path path, KeyPair keyPair) throws IOException {
        String base64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PRIVATE KEY-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64.substring(i, Math.min(i + 64, base64.length()))).append('\n');
        }
        sb.append("-----END PRIVATE KEY-----\n");
        Files.writeString(path, sb.toString());
    }

    private void writePemPublicKey(Path path, KeyPair keyPair) throws IOException {
        String base64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PUBLIC KEY-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64.substring(i, Math.min(i + 64, base64.length()))).append('\n');
        }
        sb.append("-----END PUBLIC KEY-----\n");
        Files.writeString(path, sb.toString());
    }

    @Test
    void issuesATokenItsOwnDecoderAccepts() {
        String token = issuer.issue(identity());
        Jwt decoded = decode(token);
        assertEquals("USR0000001", decoded.getSubject());
    }

    @Test
    void carriesTheAccountAndPersonIdentifiers() {
        Jwt decoded = decode(issuer.issue(identity()));
        assertEquals("USR0000001", decoded.getSubject());
        assertEquals("PER0000001", decoded.getClaim(JwtTokenIssuer.CLAIM_PERSON_ID));
    }

    @Test
    void carriesTheAccountAddress() {
        Jwt decoded = decode(issuer.issue(identity()));
        assertEquals("someone@example.com", decoded.getClaim(JwtTokenIssuer.CLAIM_EMAIL));
    }

    @Test
    void carriesTheStandardClaims() {
        Jwt decoded = decode(issuer.issue(identity()));
        assertEquals(ISSUER, decoded.getIssuer().toString());
        assertEquals(NOW, decoded.getIssuedAt());
        assertEquals(NOW.plus(TTL), decoded.getExpiresAt());
        assertFalse(decoded.getId().isBlank(), "jti lets an issued token be traced");
    }

    @Test
    void expiresExactlyWhenTheConfiguredLifetimeElapses() {
        Jwt decoded = decode(issuer.issue(identity()));
        assertEquals(TTL.toSeconds(),
                decoded.getExpiresAt().getEpochSecond() - decoded.getIssuedAt().getEpochSecond());
    }

    @Test
    void reportsTheConfiguredLifetimeToTheCaller() {
        assertEquals(TTL, issuer.accessTokenTtl());
    }

    @Test
    void neverCarriesRolesOrPermissions() {
        String claims = decode(issuer.issue(identity())).getClaims().toString().toLowerCase();
        assertFalse(claims.contains("password"));
        assertFalse(claims.contains("roles"));
        assertFalse(claims.contains("authorities"));
        assertFalse(claims.contains("permission"));
    }

    @Test
    void neverCarriesThePasswordHash() {
        Jwt decoded = decode(issuer.issue(identity()));
        assertFalse(decoded.getClaims().values().stream()
                        .anyMatch(value -> String.valueOf(value).contains("$2")),
                "A BCrypt hash must never appear in a token");
    }

    @Test
    void givesEachIssuedTokenADistinctIdentifier() {
        String first = issuer.issue(identity());
        String second = issuer.issue(identity());
        assertNotEquals(decode(first).getId(), decode(second).getId());
        assertNotEquals(first, second);
    }

    @Test
    void rejectsATokenSignedWithADifferentSecret() throws Exception {
        KeyPair foreignPair = generateRsaKeyPair();
        Path foreignPriv = tempDir.resolve("foreign_priv.pem");
        Path foreignPub = tempDir.resolve("foreign_pub.pem");
        writePemPrivateKey(foreignPriv, foreignPair);
        writePemPublicKey(foreignPub, foreignPair);
        SecurityJwtProperties foreignProps = new SecurityJwtProperties(ISSUER, TTL,
                foreignPriv.toString(), foreignPub.toString());
        JwtTokenIssuer foreignIssuer = new JwtTokenIssuer(
                new JwtConfiguration().jwtEncoder(foreignProps), foreignProps, clock);
        String foreignToken = foreignIssuer.issue(identity());
        assertThrows(Exception.class, () -> decode(foreignToken),
                "A token signed with another key must not be accepted");
    }

    @Test
    void rejectsATokenFromAnotherIssuerEvenWithAValidSignature() {
        SecurityJwtProperties foreignProps = new SecurityJwtProperties("some-other-service", TTL,
                privateKeyPath.toString(), publicKeyPath.toString());
        JwtTokenIssuer foreignIssuer = new JwtTokenIssuer(
                new JwtConfiguration().jwtEncoder(foreignProps), foreignProps, clock);
        String foreignIssuerToken = foreignIssuer.issue(identity());
        assertThrows(Exception.class, () -> decode(foreignIssuerToken));
    }

    @Test
    void rejectsATokenThatHasAlreadyExpired() {
        Instant longAgo = NOW.minus(Duration.ofHours(2));
        SecurityJwtProperties expiredProps = new SecurityJwtProperties(ISSUER, TTL,
                privateKeyPath.toString(), publicKeyPath.toString());
        JwtTokenIssuer expiredIssuer = new JwtTokenIssuer(
                new JwtConfiguration().jwtEncoder(expiredProps), expiredProps,
                Clock.fixed(longAgo, ZoneOffset.UTC));
        String expiredToken = expiredIssuer.issue(identity());
        assertThrows(Exception.class, () -> decode(expiredToken));
    }

    @Test
    void refusesToBuildWhenPrivateKeyPathIsMissing() {
        JwtConfiguration configuration = new JwtConfiguration();
        SecurityJwtProperties missing = new SecurityJwtProperties(ISSUER, TTL,
                null, publicKeyPath.toString());
        assertThrows(IllegalStateException.class, () -> configuration.jwtEncoder(missing));
    }

    @Test
    void refusesToBuildWhenPublicKeyPathIsMissing() {
        JwtConfiguration configuration = new JwtConfiguration();
        SecurityJwtProperties missing = new SecurityJwtProperties(ISSUER, TTL,
                privateKeyPath.toString(), null);
        assertThrows(IllegalStateException.class, () -> configuration.jwtDecoder(missing));
    }

    @Test
    void refusesToBuildWhenPrivateKeyFileDoesNotExist() {
        JwtConfiguration configuration = new JwtConfiguration();
        SecurityJwtProperties missing = new SecurityJwtProperties(ISSUER, TTL,
                tempDir.resolve("nope_priv.pem").toString(), publicKeyPath.toString());
        assertThrows(IllegalStateException.class, () -> configuration.jwtEncoder(missing));
    }

    @Test
    void refusesToBuildWhenPublicKeyFileDoesNotExist() {
        JwtConfiguration configuration = new JwtConfiguration();
        SecurityJwtProperties missing = new SecurityJwtProperties(ISSUER, TTL,
                privateKeyPath.toString(), tempDir.resolve("nope_pub.pem").toString());
        assertThrows(IllegalStateException.class, () -> configuration.jwtDecoder(missing));
    }

    @Test
    void refusesToBuildWhenPrivateKeyIsInvalid() throws IOException {
        Path invalid = tempDir.resolve("invalid_priv.pem");
        Files.writeString(invalid, "-----BEGIN PRIVATE KEY-----\nINVALID\n-----END PRIVATE KEY-----\n");
        JwtConfiguration configuration = new JwtConfiguration();
        SecurityJwtProperties props = new SecurityJwtProperties(ISSUER, TTL,
                invalid.toString(), publicKeyPath.toString());
        assertThrows(IllegalStateException.class, () -> configuration.jwtEncoder(props));
    }

    @Test
    void refusesToBuildWhenPublicKeyIsInvalid() throws IOException {
        Path invalid = tempDir.resolve("invalid_pub.pem");
        Files.writeString(invalid, "-----BEGIN PUBLIC KEY-----\nINVALID\n-----END PUBLIC KEY-----\n");
        JwtConfiguration configuration = new JwtConfiguration();
        SecurityJwtProperties props = new SecurityJwtProperties(ISSUER, TTL,
                privateKeyPath.toString(), invalid.toString());
        assertThrows(IllegalStateException.class, () -> configuration.jwtDecoder(props));
    }
}
