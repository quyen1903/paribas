package com.quinnbank.core.identity.application.service;

import com.quinnbank.core.identity.application.policy.AuthenticationTimestampPolicy;
import com.quinnbank.core.identity.application.port.AuthenticationAuditRepository;
import com.quinnbank.core.identity.application.port.AuthorizationDenialAudit;
import com.quinnbank.core.identity.application.result.IdentitySubjectType;
import com.quinnbank.core.identity.domain.AuthenticationActor;
import com.quinnbank.core.identity.domain.AuthenticationAuditEvent;
import com.quinnbank.core.identity.domain.enums.AuthenticationAction;
import com.quinnbank.core.identity.domain.enums.AuthenticationDecision;
import com.quinnbank.core.identity.domain.enums.AuthenticationMethod;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
public class AuthorizationDenialAuditService implements AuthorizationDenialAudit {
    private final AuthenticationAuditRepository audits;
    private final Clock clock;

    public AuthorizationDenialAuditService(AuthenticationAuditRepository audits, Clock clock) {
        this.audits = audits;
        this.clock = clock;
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordKnown(
        UUID identityId,
        IdentitySubjectType actorType,
        String reasonCode,
        String correlationId
    ) {
        Instant now = AuthenticationTimestampPolicy.jwtCompatible(clock.instant());
        IdentityActorType domainActorType = toDomainType(actorType);
        audits.saveAll(List.of(AuthenticationAuditEvent.recordForKnownIdentity(
            identityId,
            AuthenticationActor.of(domainActorType, identityId.toString()),
            AuthenticationAction.AUTHORIZATION_DENIED,
            AuthenticationDecision.FAILURE,
            AuthenticationMethod.JWT,
            reasonCode,
            correlationId,
            now
        )));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordAnonymous(
        IdentitySubjectType expectedActorType,
        String reasonCode,
        String correlationId
    ) {
        Instant now = AuthenticationTimestampPolicy.jwtCompatible(clock.instant());
        audits.saveAll(List.of(AuthenticationAuditEvent.recordAnonymous(
            toDomainType(expectedActorType),
            AuthenticationAction.AUTHORIZATION_DENIED,
            AuthenticationDecision.FAILURE,
            AuthenticationMethod.JWT,
            reasonCode,
            correlationId,
            now
        )));
    }

    private static IdentityActorType toDomainType(IdentitySubjectType actorType) {
        return switch (actorType) {
            case RETAIL_CUSTOMER -> IdentityActorType.RETAIL_CUSTOMER;
            case BUSINESS_CUSTOMER -> IdentityActorType.BUSINESS_CUSTOMER;
            case BANK_EMPLOYEE -> IdentityActorType.BANK_EMPLOYEE;
            case BACK_OFFICE_OPERATOR -> IdentityActorType.BACK_OFFICE_OPERATOR;
            case SERVICE_ACCOUNT -> IdentityActorType.SERVICE_ACCOUNT;
            case THIRD_PARTY_PARTNER -> IdentityActorType.THIRD_PARTY_PARTNER;
            case BATCH_JOB -> IdentityActorType.BATCH_JOB;
        };
    }
}
