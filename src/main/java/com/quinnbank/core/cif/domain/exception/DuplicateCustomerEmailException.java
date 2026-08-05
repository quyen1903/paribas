package com.quinnbank.core.cif.domain.exception;

public class DuplicateCustomerEmailException extends RuntimeException {
    public DuplicateCustomerEmailException(String email) {
        super("Customer email already exists: " + email);
    }
}
