package com.quinnbank.core.cif.application.exception;

public class CustomerIdentityProvisioningRejectedException extends RuntimeException {
    public CustomerIdentityProvisioningRejectedException() {
        super("The customer is not eligible for identity provisioning.");
    }
}
