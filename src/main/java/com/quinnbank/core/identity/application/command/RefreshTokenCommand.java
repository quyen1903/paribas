package com.quinnbank.core.identity.application.command;

import java.util.Objects;

public record RefreshTokenCommand(
    String refreshToken,
    String correlationId,
    String sourceAddress
) {
    public RefreshTokenCommand {
        Objects.requireNonNull(refreshToken, "refreshToken is required.");
        Objects.requireNonNull(correlationId, "correlationId is required.");
        Objects.requireNonNull(sourceAddress, "sourceAddress is required.");
    }

    @Override
    public String toString() {
        return "RefreshTokenCommand[redacted]";
    }
}
