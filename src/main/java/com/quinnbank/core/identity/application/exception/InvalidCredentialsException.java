package com.quinnbank.core.identity.application.exception;

public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException() {
        super("The supplied credentials are invalid.");
    }
}
