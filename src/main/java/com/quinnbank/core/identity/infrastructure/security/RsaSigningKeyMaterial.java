package com.quinnbank.core.identity.infrastructure.security;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

public record RsaSigningKeyMaterial(
        String keyId,
        RSAPublicKey publicKey,
        RSAPrivateKey privateKey,
        String publicKeySha256
) {
    public RsaSigningKeyMaterial {
        Objects.requireNonNull(keyId, "keyId is required.");
        Objects.requireNonNull(publicKey, "publicKey is required.");
        Objects.requireNonNull(privateKey, "privateKey is required.");
        Objects.requireNonNull(publicKeySha256, "publicKeySha256 is required.");
    }

    @Override
    public String toString() {
        return "RsaSigningKeyMaterial[keyId=redacted, publicKey=redacted, privateKey=redacted]";
    }
}
