package com.quinnbank.core.identity.infrastructure.security;

import com.quinnbank.core.identity.application.exception.AuthenticationRateLimitExceededException;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class InMemoryAuthenticationThrottleTest {
    private static final Instant WINDOW_START = Instant.parse("2026-08-04T14:00:00Z");

    @Test
    void registrationAndRefreshLimitsAreIndependentAndResetAfterOneMinute() {
        InMemoryAuthenticationThrottle throttle = new InMemoryAuthenticationThrottle(1, 10, 10, 1);

        assertDoesNotThrow(() -> throttle.checkRegistration("192.0.2.10", WINDOW_START));
        assertThrows(
                AuthenticationRateLimitExceededException.class,
                () -> throttle.checkRegistration("192.0.2.10", WINDOW_START.plusSeconds(59))
        );
        assertDoesNotThrow(() -> throttle.checkRefresh("192.0.2.10", WINDOW_START));
        assertThrows(
                AuthenticationRateLimitExceededException.class,
                () -> throttle.checkRefresh("192.0.2.10", WINDOW_START.plusSeconds(59))
        );
        assertDoesNotThrow(
                () -> throttle.checkRegistration("192.0.2.10", WINDOW_START.plus(Duration.ofMinutes(1)))
        );
        assertDoesNotThrow(
                () -> throttle.checkRefresh("192.0.2.10", WINDOW_START.plus(Duration.ofMinutes(1)))
        );
    }

    @Test
    void loginIsBoundedByBothSourceAndCanonicalIdentifier() {
        InMemoryAuthenticationThrottle identifierThrottle = new InMemoryAuthenticationThrottle(10, 10, 1, 10);
        assertDoesNotThrow(
                () -> identifierThrottle.checkLogin(
                        "192.0.2.11",
                        "retail-user@example.invalid",
                        WINDOW_START
                )
        );
        assertThrows(
                AuthenticationRateLimitExceededException.class,
                () -> identifierThrottle.checkLogin(
                        "192.0.2.12",
                        "retail-user@example.invalid",
                        WINDOW_START.plusSeconds(1)
                )
        );
        assertDoesNotThrow(
                () -> identifierThrottle.checkLogin(
                        "192.0.2.12",
                        "another-user@example.invalid",
                        WINDOW_START.plusSeconds(2)
                )
        );

        InMemoryAuthenticationThrottle sourceThrottle = new InMemoryAuthenticationThrottle(10, 1, 10, 10);
        assertDoesNotThrow(
                () -> sourceThrottle.checkLogin(
                        "192.0.2.13",
                        "retail-user@example.invalid",
                        WINDOW_START
                )
        );
        assertThrows(
                AuthenticationRateLimitExceededException.class,
                () -> sourceThrottle.checkLogin(
                        "192.0.2.13",
                        "another-user@example.invalid",
                        WINDOW_START.plusSeconds(1)
                )
        );
    }
}
