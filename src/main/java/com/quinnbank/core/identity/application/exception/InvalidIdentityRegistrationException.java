package com.quinnbank.core.identity.application.exception;

public class InvalidIdentityRegistrationException extends RuntimeException {
    public InvalidIdentityRegistrationException() {
        super("The identity registration request is invalid.");
    }
}
