package com.quinnbank.core.identity.infrastructure.security;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JdkRsaSigningKeyMaterialGeneratorTest {

    @Test
    void generatesDistinctRsa3072MaterialAndReleasesPrivateReferences() {
        JdkRsaSigningKeyMaterialGenerator generator = new JdkRsaSigningKeyMaterialGenerator();
        RsaSigningKeyMaterial first = generator.generate();
        RsaSigningKeyMaterial second = generator.generate();

        BigInteger firstPrivateModulus;
        BigInteger secondPrivateModulus;
        try {
            firstPrivateModulus = first.privateKey().getModulus();
            secondPrivateModulus = second.privateKey().getModulus();
            assertAll(
                    () -> assertEquals(RsaPublicKeyCodec.MINIMUM_RSA_BITS, first.publicKey().getModulus().bitLength()),
                    () -> assertEquals(RsaPublicKeyCodec.MINIMUM_RSA_BITS, second.publicKey().getModulus().bitLength()),
                    () -> assertEquals(first.publicKey().getModulus(), firstPrivateModulus),
                    () -> assertEquals(second.publicKey().getModulus(), secondPrivateModulus),
                    () -> assertNotEquals(first.keyId(), second.keyId()),
                    () -> assertNotEquals(first.publicKey().getModulus(), second.publicKey().getModulus()),
                    () -> assertEquals(fingerprint(first), first.publicKeySha256()),
                    () -> assertEquals(fingerprint(second), second.publicKeySha256())
            );
        } finally {
            first.close();
            second.close();
        }

        assertAll(
                () -> assertThrows(IllegalStateException.class, first::privateKey),
                () -> assertThrows(IllegalStateException.class, second::privateKey)
        );
    }

    private static String fingerprint(RsaSigningKeyMaterial material) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(material.publicKey().getEncoded())
            );
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new AssertionError(exception);
        }
    }
}
