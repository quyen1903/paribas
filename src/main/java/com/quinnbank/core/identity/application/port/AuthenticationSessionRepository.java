package com.quinnbank.core.identity.application.port;

import com.quinnbank.core.identity.domain.AuthenticationSession;

import java.util.Optional;
import java.util.UUID;

public interface AuthenticationSessionRepository {
    Optional<AuthenticationSession> findById(UUID sessionId);

    Optional<AuthenticationSession> findByIdForUpdate(UUID sessionId);

    AuthenticationSession save(AuthenticationSession authenticationSession);
}
