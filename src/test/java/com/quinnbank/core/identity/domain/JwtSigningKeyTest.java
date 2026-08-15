package com.quinnbank.core.identity.domain;

import com.quinnbank.core.identity.domain.enums.JwtSigningAlgorithm;
import com.quinnbank.core.identity.domain.enums.JwtSigningKeyStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtSigningKeyTest {
    private static final Instant CREATED_AT = Instant.parse("2026-08-04T00:00:00Z");
    private static byte[] publicKeyDer;
    private static String publicKeyFingerprint;

    @BeforeAll
    static void generateSyntheticPublicKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3_072);
        publicKeyDer = generator.generateKeyPair().getPublic().getEncoded();
        publicKeyFingerprint = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(publicKeyDer)
        );
    }

    @Test
    void registerAcceptsCanonicalRsaPublicMaterialAndDefensivelyCopiesIt() {
        byte[] mutableInput = publicKeyDer.clone();

        JwtSigningKey key = JwtSigningKey.register(
                "identity-rs256-2026-08",
                mutableInput,
                publicKeyFingerprint,
                CREATED_AT
        );
        mutableInput[0] ^= 1;
        byte[] firstRead = key.getPublicKeyDer();
        byte[] secondRead = key.getPublicKeyDer();
        firstRead[0] ^= 1;

        assertAll(
                () -> assertEquals("identity-rs256-2026-08", key.getKeyId()),
                () -> assertEquals(JwtSigningAlgorithm.RS256, key.getAlgorithm()),
                () -> assertEquals(JwtSigningKeyStatus.VERIFY_ONLY, key.getStatus()),
                () -> assertEquals(publicKeyFingerprint, key.getPublicKeySha256()),
                () -> assertArrayEquals(publicKeyDer, secondRead),
                () -> assertNotSame(firstRead, secondRead),
                () -> assertTrue(key.matchesMaterial(publicKeyDer, publicKeyFingerprint)),
                () -> assertTrue(key.canVerify(CREATED_AT)),
                () -> assertEquals(CREATED_AT, key.getVerifyOnlyAt()),
                () -> assertNull(key.getRevokedAt())
        );
    }

    @Test
    void registrationRejectsMismatchedOrMalformedPublicMaterial() {
        String wrongFingerprint = "0".repeat(64);

        assertAll(
                () -> assertThrows(
                        IllegalArgumentException.class,
                        () -> JwtSigningKey.register(
                                "identity-rs256-wrong-fingerprint",
                                publicKeyDer,
                                wrongFingerprint,
                                CREATED_AT
                        )
                ),
                () -> assertThrows(
                        IllegalArgumentException.class,
                        () -> JwtSigningKey.register(
                                "identity-rs256-invalid-der",
                                new byte[300],
                                wrongFingerprint,
                                CREATED_AT
                        )
                ),
                () -> assertThrows(
                        IllegalArgumentException.class,
                        () -> JwtSigningKey.register(
                                "invalid key id",
                                publicKeyDer,
                                publicKeyFingerprint,
                                CREATED_AT
                        )
                )
        );
    }

    @Test
    void verificationKeyCanBeRevokedWithoutReactivation() {
        JwtSigningKey key = registeredKey();

        assertAll(
                () -> assertEquals(JwtSigningKeyStatus.VERIFY_ONLY, key.getStatus()),
                () -> assertTrue(key.canVerify(CREATED_AT)),
                () -> assertEquals(CREATED_AT, key.getVerifyOnlyAt()),
                () -> assertNull(key.getRevokedAt())
        );

        Instant revokedAt = CREATED_AT.plusSeconds(60);
        key.revoke(revokedAt);

        assertAll(
                () -> assertEquals(JwtSigningKeyStatus.REVOKED, key.getStatus()),
                () -> assertFalse(key.canVerify(revokedAt)),
                () -> assertEquals(revokedAt, key.getRevokedAt()),
                () -> assertThrows(IllegalStateException.class, () -> key.revoke(revokedAt)),
                () -> assertFalse(key.toString().contains(publicKeyFingerprint))
        );
    }

    @Test
    void backwardsLifecycleTimeIsRejectedWithoutMutation() {
        JwtSigningKey key = registeredKey();

        assertThrows(
                IllegalArgumentException.class,
                () -> key.revoke(CREATED_AT.minusSeconds(1))
        );
        assertAll(
                () -> assertEquals(JwtSigningKeyStatus.VERIFY_ONLY, key.getStatus()),
                () -> assertEquals(CREATED_AT, key.getUpdatedAt()),
                () -> assertEquals(CREATED_AT, key.getVerifyOnlyAt()),
                () -> assertNull(key.getRevokedAt())
        );
    }

    @Test
    void materialComparisonRejectsChangedValuesAndInvalidFingerprintShape() {
        JwtSigningKey key = registeredKey();
        byte[] changedPublicKey = publicKeyDer.clone();
        changedPublicKey[changedPublicKey.length - 1] ^= 1;

        assertAll(
                () -> assertFalse(key.matchesMaterial(changedPublicKey, publicKeyFingerprint)),
                () -> assertFalse(key.matchesMaterial(publicKeyDer, publicKeyFingerprint.toUpperCase())),
                () -> assertFalse(key.matchesMaterial(null, publicKeyFingerprint)),
                () -> assertFalse(key.matchesMaterial(publicKeyDer, null))
        );
    }

    private static JwtSigningKey registeredKey() {
        return JwtSigningKey.register(
                "identity-rs256-test",
                publicKeyDer,
                publicKeyFingerprint,
                CREATED_AT
        );
    }
}
