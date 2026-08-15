package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.application.port.JwtSigningKeyRepository;
import com.quinnbank.core.identity.domain.JwtSigningKey;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public class JwtSigningKeyPersistenceAdapter implements JwtSigningKeyRepository {
    private final SpringDataJwtSigningKeyRepository repository;

    public JwtSigningKeyPersistenceAdapter(SpringDataJwtSigningKeyRepository repository) {
        this.repository = repository;
    }

    @Override
    public Optional<JwtSigningKey> findByKeyId(String keyId) {
        return repository.findById(keyId);
    }

    @Override
    public JwtSigningKey save(JwtSigningKey signingKey) {
        return repository.save(signingKey);
    }
}
