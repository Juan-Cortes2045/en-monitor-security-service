package com.energymonitor.security.infrastructure;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the RSA key pair from the PEM files named by {@code security.jwt.private-key-path} and
 * {@code security.jwt.public-key-path}.
 *
 * <p>Both of the formats OpenSSL produces in practice are accepted, because which one a
 * developer ends up with depends on the command they ran and on its version:
 *
 * <ul>
 *   <li>{@code BEGIN PRIVATE KEY} - PKCS#8, the unencrypted output of
 *       {@code openssl genpkey -algorithm RSA}.</li>
 *   <li>{@code BEGIN RSA PRIVATE KEY} - PKCS#1, what {@code openssl genrsa} and the traditional
 *       {@code RSA PRIVATE KEY} file use. It has no Java {@code KeySpec} of its own, so the
 *       nine CRT integers are read out of the DER sequence and handed to
 *       {@link RSAPrivateCrtKeySpec}.</li>
 *   <li>{@code BEGIN PUBLIC KEY} - X.509 SubjectPublicKeyInfo, the output of
 *       {@code openssl rsa -pubout}.</li>
 *   <li>{@code BEGIN RSA PUBLIC KEY} - PKCS#1, the output of
 *       {@code openssl rsa -RSAPublicKey_out}.</li>
 * </ul>
 *
 * <p>The label decides the parser rather than being decoration, and a label that contradicts
 * the key the caller asked for is reported instead of being parsed: pointing the application at
 * the public key where the private one belongs is a deployment mistake worth naming. A file with
 * no label at all is sniffed, so a bare base64 blob still loads.
 *
 * <p>Whitespace is removed before decoding, which covers the CR, LF, tab and space characters
 * that line-wrapped PEM picked up on the way in: a Windows file, a file with trailing spaces
 * after the dashes, and a single-line body all decode identically.
 */
final class PemRsaKeys {

    private static final String RSA = "RSA";
    private static final String PKCS8_PRIVATE = "PRIVATE KEY";
    private static final String PKCS1_PRIVATE = "RSA PRIVATE KEY";
    private static final String ENCRYPTED_PRIVATE = "ENCRYPTED PRIVATE KEY";
    private static final String X509_PUBLIC = "PUBLIC KEY";
    private static final String PKCS1_PUBLIC = "RSA PUBLIC KEY";

    private static final Pattern BEGIN_LABEL =
            Pattern.compile("-----BEGIN\\s+([A-Za-z0-9 ]*)-----");
    private static final Pattern END_LABEL = Pattern.compile("-----END");
    private static final Pattern WHITESPACE = Pattern.compile("\\s");

    private PemRsaKeys() {
    }

    /**
     * Reads the RSA private key held in a PEM file.
     *
     * @param path location of the file
     * @return the key, whether the file holds PKCS#8 or PKCS#1
     * @throws IllegalStateException if the file is missing, unreadable or not a private key
     */
    static RSAPrivateKey readPrivateKey(Path path) {
        PemDocument document = read(path, "private");
        String label = document.label();
        if (label == null || PKCS8_PRIVATE.equals(label)) {
            return fromPkcs8(document.der(), path, label == null);
        }
        if (PKCS1_PRIVATE.equals(label)) {
            return fromPkcs1(document.der(), path);
        }
        if (ENCRYPTED_PRIVATE.equals(label)) {
            throw new IllegalStateException("The RSA private key at " + path
                    + " is passphrase-protected, which this application cannot do with: decrypt it"
                    + " first, for example"
                    + " 'openssl pkcs8 -in " + path + " -out " + path + ".plain.pem'");
        }
        if (X509_PUBLIC.equals(label) || PKCS1_PUBLIC.equals(label)) {
            throw new IllegalStateException("The file at " + path
                    + " holds an RSA public key but security.jwt.private-key-path points at it."
                    + " The private key and the public key are two different files.");
        }
        throw new IllegalStateException("Unsupported PEM label '" + label + "' on the RSA private"
                + " key at " + path + ". Expected 'PRIVATE KEY' (PKCS#8) or 'RSA PRIVATE KEY'"
                + " (PKCS#1).");
    }

    /**
     * Reads the RSA public key held in a PEM file.
     *
     * @param path location of the file
     * @return the key, whether the file holds an X.509 SubjectPublicKeyInfo or PKCS#1
     * @throws IllegalStateException if the file is missing, unreadable or not a public key
     */
    static RSAPublicKey readPublicKey(Path path) {
        PemDocument document = read(path, "public");
        String label = document.label();
        if (label == null || X509_PUBLIC.equals(label)) {
            return fromX509(document.der(), path, label == null);
        }
        if (PKCS1_PUBLIC.equals(label)) {
            return fromPkcs1Public(document.der(), path);
        }
        if (PKCS8_PRIVATE.equals(label) || PKCS1_PRIVATE.equals(label)
                || ENCRYPTED_PRIVATE.equals(label)) {
            throw new IllegalStateException("The file at " + path
                    + " holds an RSA private key but security.jwt.public-key-path points at it."
                    + " The public key is a separate file, generated with"
                    + " 'openssl rsa -in private.pem -pubout -out public.pem'.");
        }
        throw new IllegalStateException("Unsupported PEM label '" + label + "' on the RSA public"
                + " key at " + path + ". Expected 'PUBLIC KEY' (X.509) or 'RSA PUBLIC KEY'"
                + " (PKCS#1).");
    }

    private static PemDocument read(Path path, String what) {
        String text;
        try {
            text = Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read the RSA " + what + " key PEM at " + path, e);
        }
        Matcher header = BEGIN_LABEL.matcher(text);
        if (!header.find()) {
            return new PemDocument(null, decodeBody(text, path, what));
        }
        String label = header.group(1).trim().toUpperCase(Locale.ROOT);
        String body = text.substring(header.end());
        Matcher end = END_LABEL.matcher(body);
        if (end.find()) {
            body = body.substring(0, end.start());
        }
        return new PemDocument(label, decodeBody(body, path, what));
    }

    private static byte[] decodeBody(String body, Path path, String what) {
        String base64 = WHITESPACE.matcher(body).replaceAll("");
        if (base64.isEmpty()) {
            throw new IllegalStateException("The RSA " + what + " key PEM at " + path
                    + " carries no key material");
        }
        try {
            return Base64.getMimeDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("The RSA " + what + " key PEM at " + path
                    + " is not valid base64", e);
        }
    }

    private static RSAPrivateKey fromPkcs8(byte[] der, Path path, boolean mayBePkcs1) {
        try {
            return (RSAPrivateKey) keyFactory().generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException | ClassCastException e) {
            if (mayBePkcs1) {
                return fromPkcs1(der, path);
            }
            throw new IllegalStateException("The RSA private key at " + path
                    + " is not a valid PKCS#8 key", e);
        }
    }

    private static RSAPrivateKey fromPkcs1(byte[] der, Path path) {
        RSAPrivateCrtKeySpec spec;
        try {
            spec = pkcs1PrivateSpec(der, path);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("The RSA private key at " + path
                    + " is not a valid PKCS#1 key", e);
        }
        try {
            return (RSAPrivateKey) keyFactory().generatePrivate(spec);
        } catch (GeneralSecurityException | ClassCastException e) {
            throw new IllegalStateException("The RSA private key at " + path
                    + " is not a valid PKCS#1 key", e);
        }
    }

    private static RSAPublicKey fromX509(byte[] der, Path path, boolean mayBePkcs1) {
        try {
            return (RSAPublicKey) keyFactory().generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | ClassCastException e) {
            if (mayBePkcs1) {
                return fromPkcs1Public(der, path);
            }
            throw new IllegalStateException("The RSA public key at " + path
                    + " is not a valid X.509 SubjectPublicKeyInfo", e);
        }
    }

    private static RSAPublicKey fromPkcs1Public(byte[] der, Path path) {
        BigInteger modulus;
        BigInteger exponent;
        try {
            DerCursor cursor = new DerCursor(der, path).readSequence();
            modulus = cursor.nextInteger();
            exponent = cursor.nextInteger();
        } catch (IllegalStateException e) {
            throw new IllegalStateException("The RSA public key at " + path
                    + " is not a valid PKCS#1 key", e);
        }
        try {
            return (RSAPublicKey) keyFactory().generatePublic(
                    new RSAPublicKeySpec(modulus, exponent));
        } catch (GeneralSecurityException | ClassCastException e) {
            throw new IllegalStateException("The RSA public key at " + path
                    + " is not a valid PKCS#1 key", e);
        }
    }

    private static RSAPrivateCrtKeySpec pkcs1PrivateSpec(byte[] der, Path path)
            throws GeneralSecurityException {
        DerCursor cursor = new DerCursor(der, path).readSequence();
        BigInteger version = cursor.nextInteger();
        if (version.intValue() != 0 && version.intValue() != 1) {
            throw new IllegalStateException("The RSA private key at " + path
                    + " declares PKCS#1 version " + version + ", which is not a two-prime key");
        }
        BigInteger modulus = cursor.nextInteger();
        BigInteger publicExponent = cursor.nextInteger();
        BigInteger privateExponent = cursor.nextInteger();
        BigInteger primeP = cursor.nextInteger();
        BigInteger primeQ = cursor.nextInteger();
        BigInteger exponentP = cursor.nextInteger();
        BigInteger exponentQ = cursor.nextInteger();
        BigInteger coefficient = cursor.nextInteger();
        return new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent,
                primeP, primeQ, exponentP, exponentQ, coefficient);
    }

    private static KeyFactory keyFactory() throws GeneralSecurityException {
        return KeyFactory.getInstance(RSA);
    }

    private record PemDocument(String label, byte[] der) {
    }

    /**
     * The slice of ASN.1 DER a PKCS#1 key needs: a sequence of tagged, length-prefixed values.
     * Only reading is implemented, and only far enough to pull the RSA integers out.
     */
    private static final class DerCursor {

        private static final int TAG_INTEGER = 0x02;
        private static final int TAG_SEQUENCE = 0x30;

        private final byte[] data;
        private final Path path;
        private int position;

        private DerCursor(byte[] data, Path path) {
            this.data = data;
            this.path = path;
        }

        private DerCursor readSequence() {
            if (readTag() != TAG_SEQUENCE) {
                throw malformed("expected a DER SEQUENCE");
            }
            return new DerCursor(readContent(), path);
        }

        private BigInteger nextInteger() {
            if (readTag() != TAG_INTEGER) {
                throw malformed("expected a DER INTEGER");
            }
            byte[] content = readContent();
            int offset = 0;
            while (offset < content.length - 1 && content[offset] == 0) {
                offset++;
            }
            return new BigInteger(1, Arrays.copyOfRange(content, offset, content.length));
        }

        private int readTag() {
            if (position >= data.length) {
                throw malformed("the DER value ends before the key does");
            }
            return data[position++] & 0xFF;
        }

        private byte[] readContent() {
            if (position >= data.length) {
                throw malformed("a DER length is missing");
            }
            int first = data[position++] & 0xFF;
            int length;
            if (first < 0x80) {
                length = first;
            } else {
                int byteCount = first & 0x7F;
                if (byteCount == 0 || byteCount > 4 || position + byteCount > data.length) {
                    throw malformed("unsupported DER length encoding");
                }
                length = 0;
                for (int i = 0; i < byteCount; i++) {
                    length = (length << 8) | (data[position++] & 0xFF);
                }
            }
            if (length < 0 || position + length > data.length) {
                throw malformed("a DER value is truncated");
            }
            byte[] content = Arrays.copyOfRange(data, position, position + length);
            position += length;
            return content;
        }

        private IllegalStateException malformed(String reason) {
            return new IllegalStateException("The RSA key at " + path
                    + " is not valid DER: " + reason);
        }
    }
}
