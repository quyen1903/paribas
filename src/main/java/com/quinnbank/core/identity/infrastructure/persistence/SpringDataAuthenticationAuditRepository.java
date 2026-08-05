package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.domain.AuthenticationAuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

interface SpringDataAuthenticationAuditRepository extends JpaRepository<AuthenticationAuditEvent, UUID> {
}
