package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.application.port.JwtSigningKeyRepository;
import com.quinnbank.core.identity.domain.JwtSigningKey;
import com.quinnbank.core.identity.domain.enums.JwtSigningKeyStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
@Transactional
class JwtSigningKeyRotationPersistenceTest {
    private static byte[] initialPublicKeyDer;
    private static String initialFingerprint;
    private static byte[] replacementPublicKeyDer;
    private static String replacementFingerprint;

    @Autowired
    private JwtSigningKeyRepository signingKeys;

    @BeforeAll
    static void generateEphemeralPublicKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3_072);
        RSAPublicKey initial = (RSAPublicKey) generator.generateKeyPair().getPublic();
        RSAPublicKey replacement = (RSAPublicKey) generator.generateKeyPair().getPublic();
        initialPublicKeyDer = initial.getEncoded();
        initialFingerprint = fingerprint(initialPublicKeyDer);
        replacementPublicKeyDer = replacement.getEncoded();
        replacementFingerprint = fingerprint(replacementPublicKeyDer);
    }

    @Test
    void demotesTheCurrentKeyBeforeInsertingItsActiveReplacement() {
        Instant now = Instant.now();
        JwtSigningKey current = signingKeys.findActiveForUpdate().orElseGet(() -> signingKeys.save(
                JwtSigningKey.register(
                        uniqueKeyId("initial"),
                        initialPublicKeyDer,
                        initialFingerprint,
                        now.minusSeconds(1)
                )
        ));
        Instant transitionTime = current.getUpdatedAt().isAfter(now) ? current.getUpdatedAt() : now;

        current.restrictToVerification(transitionTime);
        signingKeys.save(current);
        JwtSigningKey replacement = signingKeys.save(JwtSigningKey.register(
                uniqueKeyId("replacement"),
                replacementPublicKeyDer,
                replacementFingerprint,
                transitionTime
        ));

        assertEquals(JwtSigningKeyStatus.VERIFY_ONLY, current.getStatus());
        assertEquals(JwtSigningKeyStatus.ACTIVE, replacement.getStatus());
        assertEquals(replacement.getKeyId(), signingKeys.findActiveForUpdate().orElseThrow().getKeyId());
    }

    private static String fingerprint(byte[] publicKeyDer) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicKeyDer));
    }

    private static String uniqueKeyId(String prefix) {
        return "test-" + prefix + "-" + UUID.randomUUID();
    }
}
