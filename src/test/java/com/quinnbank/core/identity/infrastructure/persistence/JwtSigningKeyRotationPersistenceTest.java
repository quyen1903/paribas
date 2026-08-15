package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.application.port.JwtSigningKeyRepository;
import com.quinnbank.core.identity.domain.JwtSigningKey;
import com.quinnbank.core.identity.domain.enums.JwtSigningKeyStatus;
import jakarta.persistence.EntityManager;
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
import static org.junit.jupiter.api.Assertions.assertFalse;

@SpringBootTest
@Transactional
class JwtSigningKeyRotationPersistenceTest {
    private static byte[] initialPublicKeyDer;
    private static String initialFingerprint;
    private static byte[] replacementPublicKeyDer;
    private static String replacementFingerprint;

    @Autowired
    private JwtSigningKeyRepository signingKeys;

    @Autowired
    private EntityManager entityManager;

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
    void persistsMultipleVerificationKeysWithoutGlobalActiveKeyRotation() {
        Instant now = Instant.now();
        JwtSigningKey initial = signingKeys.save(JwtSigningKey.register(
                uniqueKeyId("initial"),
                initialPublicKeyDer,
                initialFingerprint,
                now.minusSeconds(1)
        ));
        JwtSigningKey replacement = signingKeys.save(JwtSigningKey.register(
                uniqueKeyId("replacement"),
                replacementPublicKeyDer,
                replacementFingerprint,
                now
        ));
        entityManager.flush();
        entityManager.clear();

        JwtSigningKey storedInitial = signingKeys.findByKeyId(initial.getKeyId()).orElseThrow();
        JwtSigningKey storedReplacement = signingKeys.findByKeyId(replacement.getKeyId()).orElseThrow();
        assertEquals(JwtSigningKeyStatus.VERIFY_ONLY, storedInitial.getStatus());
        assertEquals(JwtSigningKeyStatus.VERIFY_ONLY, storedReplacement.getStatus());
        assertEquals(initial.getKeyId(), storedInitial.getKeyId());
        assertEquals(replacement.getKeyId(), storedReplacement.getKeyId());

        Number obsoleteActiveIndexCount = (Number) entityManager.createNativeQuery("""
                SELECT COUNT(*)
                FROM pg_indexes
                WHERE schemaname = 'identity'
                  AND indexname = 'uk_jwt_signing_keys_single_active'
                """).getSingleResult();
        String statusConstraint = (String) entityManager.createNativeQuery("""
                SELECT pg_get_constraintdef(constraint_row.oid)
                FROM pg_constraint constraint_row
                JOIN pg_class table_row ON table_row.oid = constraint_row.conrelid
                JOIN pg_namespace schema_row ON schema_row.oid = table_row.relnamespace
                WHERE schema_row.nspname = 'identity'
                  AND table_row.relname = 'jwt_signing_keys'
                  AND constraint_row.conname = 'ck_jwt_signing_keys_status'
                """).getSingleResult();
        assertEquals(0L, obsoleteActiveIndexCount.longValue());
        assertFalse(statusConstraint.contains("ACTIVE"));
    }

    private static String fingerprint(byte[] publicKeyDer) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicKeyDer));
    }

    private static String uniqueKeyId(String prefix) {
        return "test-" + prefix + "-" + UUID.randomUUID();
    }
}
