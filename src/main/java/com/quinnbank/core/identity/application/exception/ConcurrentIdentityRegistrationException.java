package com.quinnbank.core.identity.application.exception;

public class ConcurrentIdentityRegistrationException extends RuntimeException {
    public ConcurrentIdentityRegistrationException() {
        super("Identity registration could not be completed.");
    }
}
