package com.quinnbank.core.identity.application.command;

import java.util.Objects;

public record RegisterIdentityCommand(
        String loginIdentifier,
        String rawPassword,
        String correlationId,
        String sourceAddress
) {
    public RegisterIdentityCommand {
        Objects.requireNonNull(loginIdentifier, "loginIdentifier is required.");
        Objects.requireNonNull(rawPassword, "rawPassword is required.");
        Objects.requireNonNull(correlationId, "correlationId is required.");
        Objects.requireNonNull(sourceAddress, "sourceAddress is required.");
    }

    @Override
    public String toString() {
        return "RegisterIdentityCommand[redacted]";
    }
}
