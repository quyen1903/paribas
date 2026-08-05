package com.quinnbank.core.identity.application.policy;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Canonical timestamp precision shared by authentication sessions and JWT
 * NumericDate claims. JWT timestamps are represented as whole epoch seconds.
 */
public final class AuthenticationTimestampPolicy {
    private AuthenticationTimestampPolicy() {
    }

    public static Instant jwtCompatible(Instant value) {
        if (value == null) {
            throw new IllegalArgumentException("timestamp is required.");
        }
        return value.truncatedTo(ChronoUnit.SECONDS);
    }
}
