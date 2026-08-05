package com.quinnbank.core.identity.application.exception;

public class SigningKeyUnavailableException extends RuntimeException {
    public SigningKeyUnavailableException() {
        super("Token signing material is unavailable.");
    }
}
