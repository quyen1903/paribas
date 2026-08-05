package com.quinnbank.core.identity.application.exception;

public class IdentityAlreadyExistsException extends RuntimeException {
    public IdentityAlreadyExistsException() {
        super("Identity registration could not be completed.");
    }
}
