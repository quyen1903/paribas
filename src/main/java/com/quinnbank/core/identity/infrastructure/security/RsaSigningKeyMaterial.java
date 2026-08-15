package com.quinnbank.core.identity.infrastructure.security;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;
import javax.security.auth.DestroyFailedException;

public final class RsaSigningKeyMaterial implements AutoCloseable {
    private final String keyId;
    private final RSAPublicKey publicKey;
    private final String publicKeySha256;
    private RSAPrivateKey privateKey;

    public RsaSigningKeyMaterial(
            String keyId,
            RSAPublicKey publicKey,
            RSAPrivateKey privateKey,
            String publicKeySha256
    ) {
        this.keyId = Objects.requireNonNull(keyId, "keyId is required.");
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey is required.");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey is required.");
        this.publicKeySha256 = Objects.requireNonNull(publicKeySha256, "publicKeySha256 is required.");
    }

    public String keyId() {
        return keyId;
    }

    public RSAPublicKey publicKey() {
        return publicKey;
    }

    public synchronized RSAPrivateKey privateKey() {
        if (privateKey == null) {
            throw new IllegalStateException("Private signing key material has been released.");
        }
        return privateKey;
    }

    public String publicKeySha256() {
        return publicKeySha256;
    }

    @Override
    public void close() {
        RSAPrivateKey keyToDestroy;
        synchronized (this) {
            keyToDestroy = privateKey;
            privateKey = null;
        }
        if (keyToDestroy == null) {
            return;
        }

        try {
            keyToDestroy.destroy();
        } catch (DestroyFailedException ignored) {
            // Some JCA providers cannot erase immutable key objects. Releasing
            // this reference is still required so the provider object can be collected.
        }
    }

    @Override
    public String toString() {
        return "RsaSigningKeyMaterial[keyId=redacted, publicKey=redacted, privateKey=redacted]";
    }
}
