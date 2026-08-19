package com.quinnbank.core.identity.application.exception;

public class IdentityProvisioningConflictException extends RuntimeException {
    public IdentityProvisioningConflictException() {
        super("The customer identity could not be provisioned because it conflicts with an existing identity.");
    }
}
