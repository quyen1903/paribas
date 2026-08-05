package com.quinnbank.core.identity.application.port;

import java.time.Instant;

public interface AuthenticationThrottle {
    void checkRegistration(String sourceAddress, Instant now);

    void checkLogin(String sourceAddress, String normalizedLoginIdentifier, Instant now);

    void checkRefresh(String sourceAddress, Instant now);
}
