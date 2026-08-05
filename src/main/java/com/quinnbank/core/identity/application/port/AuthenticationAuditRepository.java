package com.quinnbank.core.identity.application.port;

import com.quinnbank.core.identity.domain.AuthenticationAuditEvent;

import java.util.Collection;

public interface AuthenticationAuditRepository {
    void saveAll(Collection<AuthenticationAuditEvent> auditEvents);
}
