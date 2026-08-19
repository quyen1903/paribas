package com.quinnbank.core.identity.application.exception;

public class InvalidIdentityProvisioningException extends RuntimeException {
    public InvalidIdentityProvisioningException() {
        super("The customer identity provisioning request is invalid.");
    }
}
