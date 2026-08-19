package com.quinnbank.core.identity.application.service;

import com.quinnbank.core.identity.application.port.AuthenticationAuditRepository;
import com.quinnbank.core.identity.application.result.IdentitySubjectType;
import com.quinnbank.core.identity.domain.AuthenticationAuditEvent;
import com.quinnbank.core.identity.domain.enums.AuthenticationAction;
import com.quinnbank.core.identity.domain.enums.AuthenticationDecision;
import com.quinnbank.core.identity.domain.enums.AuthenticationMethod;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AuthorizationDenialAuditServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-19T08:00:00Z");
    private static final UUID IDENTITY_ID = UUID.fromString("10000000-0000-0000-0000-000000000001");

    @Test
    void recordsKnownAndAnonymousDenialsWithoutCustomerData() {
        RecordingAuditRepository audits = new RecordingAuditRepository();
        AuthorizationDenialAuditService service = new AuthorizationDenialAuditService(
            audits,
            Clock.fixed(NOW, ZoneOffset.UTC)
        );

        service.recordKnown(
            IDENTITY_ID,
            IdentitySubjectType.RETAIL_CUSTOMER,
            "CUSTOMER_BINDING_NOT_FOUND",
            "known-denial-test"
        );
        service.recordAnonymous(
            IdentitySubjectType.RETAIL_CUSTOMER,
            "CUSTOMER_SUBJECT_UNAVAILABLE",
            "anonymous-denial-test"
        );

        AuthenticationAuditEvent known = audits.events.get(0);
        AuthenticationAuditEvent anonymous = audits.events.get(1);
        assertAll(
            () -> assertEquals(IDENTITY_ID, known.getTargetIdentityId()),
            () -> assertEquals(IdentityActorType.RETAIL_CUSTOMER, known.getActorType()),
            () -> assertEquals(IDENTITY_ID.toString(), known.getActorId()),
            () -> assertEquals(AuthenticationAction.AUTHORIZATION_DENIED, known.getAction()),
            () -> assertEquals(AuthenticationDecision.FAILURE, known.getDecision()),
            () -> assertEquals(AuthenticationMethod.JWT, known.getAuthenticationMethod()),
            () -> assertEquals("CUSTOMER_BINDING_NOT_FOUND", known.getReasonCode()),
            () -> assertEquals("known-denial-test", known.getCorrelationId()),
            () -> assertEquals(NOW, known.getOccurredAt()),
            () -> assertNull(anonymous.getTargetIdentityId()),
            () -> assertEquals("ANONYMOUS", anonymous.getActorId()),
            () -> assertEquals(AuthenticationAction.AUTHORIZATION_DENIED, anonymous.getAction()),
            () -> assertEquals("CUSTOMER_SUBJECT_UNAVAILABLE", anonymous.getReasonCode())
        );
    }

    private static final class RecordingAuditRepository implements AuthenticationAuditRepository {
        private final List<AuthenticationAuditEvent> events = new ArrayList<>();

        @Override
        public void saveAll(java.util.Collection<AuthenticationAuditEvent> auditEvents) {
            events.addAll(auditEvents);
        }
    }
}
