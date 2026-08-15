package com.quinnbank.core.identity.application.port;

import com.quinnbank.core.identity.domain.JwtSigningKey;

import java.util.Optional;

public interface JwtSigningKeyRepository {
    Optional<JwtSigningKey> findByKeyId(String keyId);

    JwtSigningKey save(JwtSigningKey signingKey);
}
