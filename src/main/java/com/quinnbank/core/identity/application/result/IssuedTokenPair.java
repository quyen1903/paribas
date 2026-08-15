package com.quinnbank.core.identity.application.result;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record IssuedTokenPair(
    UUID identityId,
    String accessToken,
    Instant accessExpiresAt,
    String refreshToken,
    Instant refreshExpiresAt
) {
    public IssuedTokenPair {
        Objects.requireNonNull(identityId, "identityId is required.");
        Objects.requireNonNull(accessToken, "accessToken is required.");
        Objects.requireNonNull(accessExpiresAt, "accessExpiresAt is required.");
        Objects.requireNonNull(refreshToken, "refreshToken is required.");
        Objects.requireNonNull(refreshExpiresAt, "refreshExpiresAt is required.");
    }

    @Override
    public String toString() {
        return "IssuedTokenPair[identityId=redacted, accessToken=redacted, "
                + "accessExpiresAt=" + accessExpiresAt
                + ", refreshToken=redacted, refreshExpiresAt=" + refreshExpiresAt + "]";
    }
}
