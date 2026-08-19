package com.quinnbank.core.identity.infrastructure.security;

import com.quinnbank.core.identity.domain.EncodedPassword;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SpringPasswordServiceTest {
    private static final String DUMMY_HASH = "$2b$12$" + "d".repeat(53);
    private static final String UNUSABLE_HASH = "$2b$12$" + "u".repeat(53);

    @Test
    void unusableCredentialUsesGeneratedMaterialAndClearsTheMutableCopy() {
        byte[] generatedMaterial = new byte[32];
        for (int index = 0; index < generatedMaterial.length; index++) {
            generatedMaterial[index] = (byte) (index + 1);
        }
        String transientCredential = HexFormat.of().formatHex(generatedMaterial);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        when(encoder.encode("synthetic-timing-password-only")).thenReturn(DUMMY_HASH);
        when(encoder.encode(transientCredential)).thenReturn(UNUSABLE_HASH);
        BytesKeyGenerator generator = new FixedBytesKeyGenerator(generatedMaterial);

        EncodedPassword result = new SpringPasswordService(encoder, generator)
            .createUnusableCredential();

        verify(encoder).encode(transientCredential);
        assertArrayEquals(new byte[32], generatedMaterial);
        assertFalse(result.toString().contains(UNUSABLE_HASH));
    }

    private record FixedBytesKeyGenerator(byte[] material) implements BytesKeyGenerator {
        @Override
        public int getKeyLength() {
            return material.length;
        }

        @Override
        public byte[] generateKey() {
            return material;
        }
    }
}
