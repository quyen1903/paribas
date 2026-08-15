package com.quinnbank.core.identity.infrastructure.security;

import com.quinnbank.core.identity.application.exception.AuthenticationRateLimitExceededException;
import com.quinnbank.core.identity.application.port.AuthenticationThrottle;

import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

public class InMemoryAuthenticationThrottle implements AuthenticationThrottle {
    private static final Duration WINDOW = Duration.ofMinutes(1);
    private static final int MAX_BUCKETS = 10_000;

    private final Map<String, Bucket> buckets = new LinkedHashMap<>();
    private final int registrationLimit;
    private final int loginSourceLimit;
    private final int loginIdentifierLimit;
    private final int refreshLimit;

    public InMemoryAuthenticationThrottle(
        int registrationLimit,
        int loginSourceLimit,
        int loginIdentifierLimit,
        int refreshLimit
    ) {
        this.registrationLimit = requirePositive(registrationLimit, "registrationLimit");
        this.loginSourceLimit = requirePositive(loginSourceLimit, "loginSourceLimit");
        this.loginIdentifierLimit = requirePositive(loginIdentifierLimit, "loginIdentifierLimit");
        this.refreshLimit = requirePositive(refreshLimit, "refreshLimit");
    }

    @Override
    public synchronized void checkRegistration(String sourceAddress, Instant now) {
        consume("registration:source:" + source(sourceAddress), registrationLimit, now);
    }

    @Override
    public synchronized void checkLogin(String sourceAddress, String normalizedLoginIdentifier, Instant now) {
        consume("login:source:" + source(sourceAddress), loginSourceLimit, now);
        consume("login:identifier:" + identifier(normalizedLoginIdentifier), loginIdentifierLimit, now);
    }

    @Override
    public synchronized void checkRefresh(String sourceAddress, Instant now) {
        consume("refresh:source:" + source(sourceAddress), refreshLimit, now);
    }

    private void consume(String key, int limit, Instant now) {
        if (now == null) {
            throw new IllegalArgumentException("now is required.");
        }

        removeExpired(now);
        Bucket bucket = buckets.get(key);
        if (bucket == null) {
            if (buckets.size() >= MAX_BUCKETS) {
                throw new AuthenticationRateLimitExceededException();
            }
            buckets.put(key, new Bucket(now, 1));
            return;
        }

        if (!now.isBefore(bucket.windowStartedAt().plus(WINDOW))) {
            buckets.put(key, new Bucket(now, 1));
            return;
        }
        if (bucket.attempts() >= limit) {
            throw new AuthenticationRateLimitExceededException();
        }
        buckets.put(key, new Bucket(bucket.windowStartedAt(), bucket.attempts() + 1));
    }

    private void removeExpired(Instant now) {
        Iterator<Map.Entry<String, Bucket>> iterator = buckets.entrySet().iterator();
        while (iterator.hasNext()) {
            Bucket bucket = iterator.next().getValue();
            if (!now.isBefore(bucket.windowStartedAt().plus(WINDOW))) {
                iterator.remove();
            }
        }
    }

    private static String source(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        String trimmed = value.trim();
        if (trimmed.length() > 64 || trimmed.chars().anyMatch(Character::isISOControl)) {
            return "invalid";
        }
        return trimmed;
    }

    private static String identifier(String value) {
        if (value == null || value.isBlank()) {
            return "invalid";
        }
        if (value.length() > 254 || value.chars().anyMatch(Character::isISOControl)) {
            return "invalid";
        }
        return value;
    }

    private static int requirePositive(int value, String fieldName) {
        if (value < 1) {
            throw new IllegalArgumentException(fieldName + " must be positive.");
        }
        return value;
    }

    private record Bucket(Instant windowStartedAt, int attempts) {
    }
}
