package com.quinnbank.core.cif.application.exception;

public class CustomerAccessDeniedException extends RuntimeException {
    public CustomerAccessDeniedException() {
        super("The authenticated subject is not allowed to access this customer profile.");
    }
}
