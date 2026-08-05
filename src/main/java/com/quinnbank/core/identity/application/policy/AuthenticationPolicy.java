package com.quinnbank.core.identity.application.policy;

import java.time.Duration;

public record AuthenticationPolicy(
        int lockThreshold,
        Duration lockDuration,
        Duration refreshTokenTtl
) {
    private static final int MAX_LOCK_THRESHOLD = 1_000;

    public AuthenticationPolicy {
        if (lockThreshold < 1 || lockThreshold > MAX_LOCK_THRESHOLD) {
            throw new IllegalArgumentException("lockThreshold is invalid.");
        }
        requirePositive(lockDuration, "lockDuration");
        requirePositive(refreshTokenTtl, "refreshTokenTtl");
    }

    private static void requirePositive(Duration value, String fieldName) {
        if (value == null || value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(fieldName + " must be positive.");
        }
    }
}
