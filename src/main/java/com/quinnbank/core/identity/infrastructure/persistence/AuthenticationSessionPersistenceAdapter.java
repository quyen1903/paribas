package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.application.port.AuthenticationSessionRepository;
import com.quinnbank.core.identity.domain.AuthenticationSession;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public class AuthenticationSessionPersistenceAdapter implements AuthenticationSessionRepository {
    private final SpringDataAuthenticationSessionRepository repository;

    public AuthenticationSessionPersistenceAdapter(SpringDataAuthenticationSessionRepository repository) {
        this.repository = repository;
    }

    @Override
    public Optional<AuthenticationSession> findById(UUID sessionId) {
        return repository.findById(sessionId);
    }

    @Override
    public Optional<AuthenticationSession> findByIdForUpdate(UUID sessionId) {
        return repository.findByIdForUpdate(sessionId);
    }

    @Override
    public AuthenticationSession save(AuthenticationSession authenticationSession) {
        return repository.save(authenticationSession);
    }
}
