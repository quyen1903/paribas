package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.application.port.AuthenticationAuditRepository;
import com.quinnbank.core.identity.domain.AuthenticationAuditEvent;
import org.springframework.stereotype.Repository;

import java.util.Collection;

@Repository
public class AuthenticationAuditPersistenceAdapter implements AuthenticationAuditRepository {
    private final SpringDataAuthenticationAuditRepository repository;

    public AuthenticationAuditPersistenceAdapter(SpringDataAuthenticationAuditRepository repository) {
        this.repository = repository;
    }

    @Override
    public void saveAll(Collection<AuthenticationAuditEvent> auditEvents) {
        repository.saveAll(auditEvents);
    }
}
