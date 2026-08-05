package com.quinnbank.core.identity.application.exception;

public class InvalidRefreshTokenException extends RuntimeException {
    public InvalidRefreshTokenException() {
        super("The refresh token is invalid or expired.");
    }
}
