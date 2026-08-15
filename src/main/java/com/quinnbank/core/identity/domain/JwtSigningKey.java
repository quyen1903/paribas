package com.quinnbank.core.identity.domain;

import com.quinnbank.core.identity.domain.enums.JwtSigningAlgorithm;
import com.quinnbank.core.identity.domain.enums.JwtSigningKeyStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;

@Entity
@Table(name = "jwt_signing_keys", schema = "identity")
public class JwtSigningKey {
    private static final int MAX_KEY_ID_LENGTH = 100;
    private static final int MIN_RSA_MODULUS_BITS = 3_072;
    private static final int MAX_RSA_MODULUS_BITS = 8_192;
    private static final int MAX_PUBLIC_KEY_DER_LENGTH = 16_384;

    @Id
    @Column(name = "key_id", nullable = false, length = MAX_KEY_ID_LENGTH, updatable = false)
    private String keyId;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    @Enumerated(EnumType.STRING)
    @Column(name = "algorithm", nullable = false, length = 10, updatable = false)
    private JwtSigningAlgorithm algorithm;

    @Column(name = "public_key_der", nullable = false, updatable = false, columnDefinition = "bytea")
    private byte[] publicKeyDer;

    @Column(name = "public_key_sha256", nullable = false, length = 64, updatable = false)
    private String publicKeySha256;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private JwtSigningKeyStatus status;

    @Column(name = "verify_only_at")
    private Instant verifyOnlyAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected JwtSigningKey() {
    }

    /**
     * Registers an RSA public key for verification of an already-issued token
     * pair. Private key material is transient and must never enter this entity.
     */
    public static JwtSigningKey register(
        String keyId,
        byte[] publicKeyDer,
        String publicKeySha256,
        Instant now
    ) {
        String requiredKeyId = requireKeyId(keyId);
        Instant requiredNow = requirePresent(now, "now");
        byte[] validatedPublicKey = validatePublicKey(publicKeyDer);
        String requiredFingerprint = requireFingerprint(publicKeySha256);
        if (!fingerprint(validatedPublicKey).equals(requiredFingerprint)) {
            throw new IllegalArgumentException("publicKeySha256 does not match publicKeyDer.");
        }

        JwtSigningKey signingKey = new JwtSigningKey();
        signingKey.keyId = requiredKeyId;
        signingKey.algorithm = JwtSigningAlgorithm.RS256;
        signingKey.publicKeyDer = validatedPublicKey;
        signingKey.publicKeySha256 = requiredFingerprint;
        signingKey.status = JwtSigningKeyStatus.VERIFY_ONLY;
        signingKey.verifyOnlyAt = requiredNow;
        signingKey.createdAt = requiredNow;
        signingKey.updatedAt = requiredNow;
        return signingKey;
    }

    public void revoke(Instant now) {
        requireTransitionTime(now);
        if (status != JwtSigningKeyStatus.VERIFY_ONLY) {
            throw new IllegalStateException("Only a verification key can be revoked.");
        }

        status = JwtSigningKeyStatus.REVOKED;
        revokedAt = now;
        updatedAt = now;
    }

    public boolean canVerify(Instant now) {
        requirePresent(now, "now");
        return status == JwtSigningKeyStatus.VERIFY_ONLY && !now.isBefore(createdAt);
    }

    public boolean matchesMaterial(byte[] candidatePublicKeyDer, String candidatePublicKeySha256) {
        if (candidatePublicKeyDer == null || candidatePublicKeySha256 == null) {
            return false;
        }
        if (!candidatePublicKeySha256.matches("[0-9a-f]{64}")) {
            return false;
        }

        return MessageDigest.isEqual(publicKeyDer, candidatePublicKeyDer)
            && MessageDigest.isEqual(
            publicKeySha256.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
            candidatePublicKeySha256.getBytes(java.nio.charset.StandardCharsets.US_ASCII)
        );
    }

    public String getKeyId() {
        return keyId;
    }

    public long getVersion() {
        return version;
    }

    public JwtSigningAlgorithm getAlgorithm() {
        return algorithm;
    }

    public byte[] getPublicKeyDer() {
        return Arrays.copyOf(publicKeyDer, publicKeyDer.length);
    }

    public String getPublicKeySha256() {
        return publicKeySha256;
    }

    public JwtSigningKeyStatus getStatus() {
        return status;
    }

    public Instant getVerifyOnlyAt() {
        return verifyOnlyAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    @Override
    public String toString() {
        return "JwtSigningKey[keyId=" + keyId + ", algorithm=" + algorithm + ", status=" + status + "]";
    }

    private void requireTransitionTime(Instant now) {
        requirePresent(now, "now");
        if (now.isBefore(updatedAt)) {
            throw new IllegalArgumentException("Transition time cannot move backwards.");
        }
    }

    private static byte[] validatePublicKey(byte[] value) {
        if (value == null || value.length == 0 || value.length > MAX_PUBLIC_KEY_DER_LENGTH) {
            throw new IllegalArgumentException("publicKeyDer has an invalid length.");
        }

        byte[] defensiveCopy = Arrays.copyOf(value, value.length);
        try {
            java.security.PublicKey decoded = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(defensiveCopy));
            if (!(decoded instanceof RSAPublicKey rsaPublicKey)
                    || !"RSA".equals(decoded.getAlgorithm())
                    || rsaPublicKey.getModulus().bitLength() < MIN_RSA_MODULUS_BITS
                    || rsaPublicKey.getModulus().bitLength() > MAX_RSA_MODULUS_BITS
                    || !Arrays.equals(decoded.getEncoded(), defensiveCopy)) {
                throw new IllegalArgumentException(
                        "publicKeyDer must be a canonical 3072-8192 bit RSA X.509 SubjectPublicKeyInfo value."
                );
            }
            return defensiveCopy;
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException(
                    "publicKeyDer must be a valid RSA X.509 SubjectPublicKeyInfo value."
            );
        }
    }

    private static String fingerprint(byte[] publicKeyDer) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicKeyDer));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Required SHA-256 provider is unavailable.", exception);
        }
    }

    private static String requireKeyId(String value) {
        if (value == null || !value.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,99}")) {
            throw new IllegalArgumentException("keyId has an invalid format.");
        }
        return value;
    }

    private static String requireFingerprint(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("publicKeySha256 must be a lowercase SHA-256 fingerprint.");
        }
        return value;
    }

    private static <T> T requirePresent(T value, String fieldName) {
        if (value == null) {
            throw new IllegalArgumentException(fieldName + " is required.");
        }
        return value;
    }
}
