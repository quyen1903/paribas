package com.quinnbank.core.identity.application.exception;

public class AuthenticationRateLimitExceededException extends RuntimeException {
    public AuthenticationRateLimitExceededException() {
        super("The authentication request was rate limited.");
    }
}
