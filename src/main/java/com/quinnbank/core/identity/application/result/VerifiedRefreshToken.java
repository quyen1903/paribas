package com.quinnbank.core.identity.application.result;

import com.quinnbank.core.identity.domain.enums.IdentityActorType;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record VerifiedRefreshToken(
        UUID identityId,
        IdentityActorType actorType,
        UUID sessionId,
        UUID tokenId,
        Instant issuedAt,
        Instant expiresAt
) {
    public VerifiedRefreshToken {
        Objects.requireNonNull(identityId, "identityId is required.");
        Objects.requireNonNull(actorType, "actorType is required.");
        Objects.requireNonNull(sessionId, "sessionId is required.");
        Objects.requireNonNull(tokenId, "tokenId is required.");
        Objects.requireNonNull(issuedAt, "issuedAt is required.");
        Objects.requireNonNull(expiresAt, "expiresAt is required.");
    }

    @Override
    public String toString() {
        return "VerifiedRefreshToken[identityId=redacted, actorType=" + actorType
                + ", sessionId=redacted, tokenId=redacted, issuedAt=" + issuedAt
                + ", expiresAt=" + expiresAt + "]";
    }
}
