package com.quinnbank.core.identity.application.port;

import com.quinnbank.core.identity.application.result.IdentitySubjectType;

import java.util.UUID;

public interface AuthorizationDenialAudit {
    void recordKnown(
        UUID identityId,
        IdentitySubjectType actorType,
        String reasonCode,
        String correlationId
    );

    void recordAnonymous(
        IdentitySubjectType expectedActorType,
        String reasonCode,
        String correlationId
    );
}
