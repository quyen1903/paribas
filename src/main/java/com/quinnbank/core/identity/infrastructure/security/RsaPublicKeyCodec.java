package com.quinnbank.core.identity.infrastructure.security;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

final class RsaPublicKeyCodec {
    static final int MINIMUM_RSA_BITS = 3_072;
    static final int MAXIMUM_RSA_BITS = 8_192;

    private RsaPublicKeyCodec() {
    }

    static RSAPublicKey decode(byte[] encoded) throws GeneralSecurityException {
        if (encoded == null || encoded.length == 0) {
            throw new GeneralSecurityException("RSA public key is missing.");
        }
        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(encoded));
        requireSupportedStrength(publicKey);
        if (!Arrays.equals(encoded, publicKey.getEncoded())) {
            throw new GeneralSecurityException("RSA public key encoding is not canonical.");
        }
        return publicKey;
    }

    static String sha256(RSAPublicKey publicKey) throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
        return HexFormat.of().formatHex(digest);
    }

    static void requireMinimumStrength(RSAPublicKey publicKey) throws GeneralSecurityException {
        if (publicKey.getModulus().bitLength() < MINIMUM_RSA_BITS) {
            throw new GeneralSecurityException("RSA public key is below the configured minimum strength.");
        }
    }

    static void requireSupportedStrength(RSAPublicKey publicKey) throws GeneralSecurityException {
        requireMinimumStrength(publicKey);
        if (publicKey.getModulus().bitLength() > MAXIMUM_RSA_BITS) {
            throw new GeneralSecurityException("RSA public key is above the configured maximum strength.");
        }
    }
}
