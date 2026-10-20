package com.energymonitor.security.infrastructure;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * Builds the JWT issuing and validating components.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SecurityJwtProperties.class)
public class JwtConfiguration {

    @Bean
    public JwtEncoder jwtEncoder(SecurityJwtProperties properties) {
        RSAPrivateKey privateKey = loadPrivateKey(properties);
        RSAPublicKey publicKey = loadPublicKey(properties);
        String kid = computeKid(publicKey);

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(kid)
                .build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(SecurityJwtProperties properties) {
        RSAPublicKey publicKey = loadPublicKey(properties);
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(properties.issuer()));
        return decoder;
    }

    @Bean
    public String jwtKeyId(SecurityJwtProperties properties) {
        return computeKid(loadPublicKey(properties));
    }

    private RSAPrivateKey loadPrivateKey(SecurityJwtProperties properties) {
        String path = properties.privateKeyPath();
        if (path == null || path.isBlank()) {
            throw new IllegalStateException("Missing RSA private key: set"
                    + " SECURITY_JWT_PRIVATE_KEY_PATH (security.jwt.private-key-path) to the file"
                    + " holding the signing key, generated with"
                    + " 'openssl genpkey -algorithm RSA -out private.pem"
                    + " -pkeyopt rsa_keygen_bits:2048'. The application refuses to start without"
                    + " it rather than signing tokens with a key nobody can rotate.");
        }
        return PemRsaKeys.readPrivateKey(Path.of(path.trim()));
    }

    private RSAPublicKey loadPublicKey(SecurityJwtProperties properties) {
        String path = properties.publicKeyPath();
        if (path == null || path.isBlank()) {
            throw new IllegalStateException("Missing RSA public key: set"
                    + " SECURITY_JWT_PUBLIC_KEY_PATH (security.jwt.public-key-path) to the file"
                    + " holding the verification key, generated with"
                    + " 'openssl rsa -in private.pem -pubout -out public.pem'."
                    + " Without it no incoming token can be validated.");
        }
        return PemRsaKeys.readPublicKey(Path.of(path.trim()));
    }

    private String computeKid(RSAPublicKey publicKey) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(publicKey.getModulus().toByteArray());
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < Math.min(8, digest.length); i++) {
                sb.append(String.format("%02x", digest[i]));
            }
            return "key-" + sb;
        } catch (NoSuchAlgorithmException e) {
            return "key-1";
        }
    }
}
