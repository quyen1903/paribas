package com.quinnbank.core.identity.infrastructure.security;

import com.quinnbank.core.identity.application.port.PasswordService;
import com.quinnbank.core.identity.domain.EncodedPassword;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.HexFormat;

public class SpringPasswordService implements PasswordService {
    private static final String DUMMY_PASSWORD = "synthetic-timing-password-only";
    private static final int UNUSABLE_CREDENTIAL_BYTES = 32;

    private final PasswordEncoder passwordEncoder;
    private final BytesKeyGenerator unusableCredentialGenerator;
    private final String dummyEncodedPassword;

    public SpringPasswordService(PasswordEncoder passwordEncoder) {
        this(passwordEncoder, KeyGenerators.secureRandom(UNUSABLE_CREDENTIAL_BYTES));
    }

    SpringPasswordService(
        PasswordEncoder passwordEncoder,
        BytesKeyGenerator unusableCredentialGenerator
    ) {
        this.passwordEncoder = passwordEncoder;
        this.unusableCredentialGenerator = unusableCredentialGenerator;
        this.dummyEncodedPassword = passwordEncoder.encode(DUMMY_PASSWORD);
    }

    @Override
    public EncodedPassword encode(String rawPassword) {
        requirePassword(rawPassword);
        return EncodedPassword.fromPasswordEncoder(passwordEncoder.encode(rawPassword));
    }

    @Override
    public EncodedPassword createUnusableCredential() {
        byte[] randomCredential = unusableCredentialGenerator.generateKey();
        try {
            String transientCredential = HexFormat.of().formatHex(randomCredential);
            return EncodedPassword.fromPasswordEncoder(passwordEncoder.encode(transientCredential));
        } finally {
            Arrays.fill(randomCredential, (byte) 0);
        }
    }

    @Override
    public boolean matches(String rawPassword, String encodedPassword) {
        requirePassword(rawPassword);
        if (encodedPassword == null || encodedPassword.isBlank()) {
            throw new IllegalArgumentException("encodedPassword is required.");
        }
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }

    @Override
    public void performDummyMatch(String rawPassword) {
        passwordEncoder.matches(rawPassword == null ? "" : rawPassword, dummyEncodedPassword);
    }

    private static void requirePassword(String rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("password is required.");
        }
    }
}
