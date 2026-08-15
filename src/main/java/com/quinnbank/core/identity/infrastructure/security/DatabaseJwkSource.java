package com.quinnbank.core.identity.infrastructure.security;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.quinnbank.core.identity.application.port.JwtSigningKeyRepository;
import com.quinnbank.core.identity.domain.JwtSigningKey;
import com.quinnbank.core.identity.domain.enums.JwtSigningAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class DatabaseJwkSource implements JWKSource<SecurityContext> {
    private static final Pattern KEY_ID_PATTERN = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,99}");

    private final JwtSigningKeyRepository signingKeys;
    private final Clock clock;
    private final Duration clockSkew;

    public DatabaseJwkSource(
        JwtSigningKeyRepository signingKeys,
        Clock clock,
        Duration clockSkew
    ) {
        this.signingKeys = signingKeys;
        this.clock = clock;
        if (clockSkew == null || clockSkew.isNegative() || clockSkew.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("clockSkew is invalid.");
        }
        this.clockSkew = clockSkew;
    }

    @Override
    public List<JWK> get(JWKSelector selector, SecurityContext context) {
        JWKMatcher matcher = selector.getMatcher();
        Set<String> keyIds = matcher.getKeyIDs();
        Set<Algorithm> algorithms = matcher.getAlgorithms();
        if (keyIds == null || keyIds.size() != 1
                || algorithms == null || !algorithms.contains(JWSAlgorithm.RS256)) {
            return List.of();
        }

        String keyId = keyIds.iterator().next();
        if (keyId == null || !KEY_ID_PATTERN.matcher(keyId).matches()) {
            return List.of();
        }

        Instant now = clock.instant().plus(clockSkew);
        JwtSigningKey signingKey = signingKeys.findByKeyId(keyId).orElse(null);
        if (signingKey == null
                || signingKey.getAlgorithm() != JwtSigningAlgorithm.RS256
                || !signingKey.canVerify(now)) {
            return List.of();
        }

        try {
            RSAPublicKey publicKey = RsaPublicKeyCodec.decode(signingKey.getPublicKeyDer());
            String decodedFingerprint = RsaPublicKeyCodec.sha256(publicKey);
            if (!MessageDigest.isEqual(
                    decodedFingerprint.getBytes(StandardCharsets.US_ASCII),
                    signingKey.getPublicKeySha256().getBytes(StandardCharsets.US_ASCII)
            )) {
                return List.of();
            }
            RSAKey jwk = new RSAKey.Builder(publicKey)
                .keyID(signingKey.getKeyId())
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .build();
            return selector.select(new JWKSet(jwk));
        } catch (GeneralSecurityException | RuntimeException exception) {
            return List.of();
        }
    }
}
