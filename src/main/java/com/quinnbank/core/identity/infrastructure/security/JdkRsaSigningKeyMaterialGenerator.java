package com.quinnbank.core.identity.infrastructure.security;

import com.quinnbank.core.identity.application.exception.SigningKeyUnavailableException;

import javax.security.auth.DestroyFailedException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

public final class JdkRsaSigningKeyMaterialGenerator implements RsaSigningKeyMaterialGenerator {
    private static final String KEY_ID_PREFIX = "ephemeral-rsa-";

    public JdkRsaSigningKeyMaterialGenerator() {
    }

    @Override
    public RsaSigningKeyMaterial generate() {
        PrivateKey generatedPrivateKey = null;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(RsaPublicKeyCodec.MINIMUM_RSA_BITS);
            KeyPair keyPair = generator.generateKeyPair();
            generatedPrivateKey = keyPair.getPrivate();
            if (!(keyPair.getPublic() instanceof RSAPublicKey publicKey)
                    || !(generatedPrivateKey instanceof RSAPrivateKey privateKey)) {
                throw new GeneralSecurityException("The RSA provider returned incompatible key material.");
            }
            RsaPublicKeyCodec.requireSupportedStrength(publicKey);
            return new RsaSigningKeyMaterial(
                    KEY_ID_PREFIX + UUID.randomUUID(),
                    publicKey,
                    privateKey,
                    RsaPublicKeyCodec.sha256(publicKey)
            );
        } catch (GeneralSecurityException | IllegalArgumentException | ProviderException exception) {
            destroyBestEffort(generatedPrivateKey);
            throw new SigningKeyUnavailableException();
        }
    }

    private static void destroyBestEffort(PrivateKey privateKey) {
        if (privateKey == null) {
            return;
        }
        try {
            privateKey.destroy();
        } catch (DestroyFailedException ignored) {
            // The caller receives no reference when generation fails. Providers
            // that cannot erase immutable keys leave collection to the JVM.
        }
    }
}
