package com.quinnbank.core.cif.application.command;

import java.util.Objects;
import java.util.UUID;

/**
 * Trusted application input for a reviewed onboarding/activation coordinator.
 * It is not an HTTP request contract.
 */
public record ProvisionIdentityForCustomerCommand(
    UUID customerId,
    String correlationId,
    String sourceAddress
) {
    public ProvisionIdentityForCustomerCommand {
        Objects.requireNonNull(customerId, "customerId is required.");
        Objects.requireNonNull(correlationId, "correlationId is required.");
        Objects.requireNonNull(sourceAddress, "sourceAddress is required.");
    }

    @Override
    public String toString() {
        return "ProvisionIdentityForCustomerCommand[redacted]";
    }
}
