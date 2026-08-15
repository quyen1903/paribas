package com.quinnbank.core.identity.api.response;

import com.quinnbank.core.identity.application.result.IssuedTokenPair;

import java.time.Instant;
import java.util.UUID;

public record TokenPairResponse(
    UUID identityId,
    String tokenType,
    String accessToken,
    Instant accessExpiresAt,
    String refreshToken,
    Instant refreshExpiresAt
) {
    private static final String BEARER_TOKEN_TYPE = "Bearer";

    public static TokenPairResponse from(IssuedTokenPair issuedTokenPair) {
        return new TokenPairResponse(
            issuedTokenPair.identityId(),
            BEARER_TOKEN_TYPE,
            issuedTokenPair.accessToken(),
            issuedTokenPair.accessExpiresAt(),
            issuedTokenPair.refreshToken(),
            issuedTokenPair.refreshExpiresAt()
        );
    }

    @Override
    public String toString() {
        return "TokenPairResponse[identityId=REDACTED, tokenType=" + tokenType
                + ", accessToken=REDACTED, accessExpiresAt=" + accessExpiresAt
                + ", refreshToken=REDACTED, refreshExpiresAt=" + refreshExpiresAt
                + "]";
    }
}
