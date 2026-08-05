package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.application.port.JwtSigningKeyRepository;
import com.quinnbank.core.identity.domain.JwtSigningKey;
import com.quinnbank.core.identity.domain.enums.JwtSigningKeyStatus;
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
    public Optional<JwtSigningKey> findActiveForUpdate() {
        return repository.findByStatusForUpdate(JwtSigningKeyStatus.ACTIVE);
    }

    @Override
    public JwtSigningKey save(JwtSigningKey signingKey) {
        // Rotation must flush the current ACTIVE key's demotion before the
        // replacement ACTIVE key is inserted. PostgreSQL enforces the
        // single-active-key partial unique index immediately, while Hibernate
        // otherwise orders inserts before updates at transaction flush time.
        return repository.saveAndFlush(signingKey);
    }
}
