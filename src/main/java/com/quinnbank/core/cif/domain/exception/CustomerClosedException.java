package com.quinnbank.core.cif.domain.exception;

import java.util.UUID;

public class CustomerClosedException extends RuntimeException {
    public CustomerClosedException(UUID customerId) {
        super("Customer profile is closed: " + customerId);
    }
}
