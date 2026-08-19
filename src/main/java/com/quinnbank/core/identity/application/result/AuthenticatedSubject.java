package com.quinnbank.core.identity.application.result;

import java.util.Objects;
import java.util.UUID;

public record AuthenticatedSubject(
    UUID identityId,
    IdentitySubjectType actorType,
    UUID subjectId
) {
    public AuthenticatedSubject {
        Objects.requireNonNull(identityId, "identityId is required.");
        Objects.requireNonNull(actorType, "actorType is required.");
        Objects.requireNonNull(subjectId, "subjectId is required.");
    }

    @Override
    public String toString() {
        return "AuthenticatedSubject[identityId=redacted, actorType=" + actorType + ", subjectId=redacted]";
    }
}
