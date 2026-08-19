package com.quinnbank.core.identity.application.result;

import java.util.Objects;
import java.util.UUID;

public record ProvisionedCustomerIdentity(
    UUID identityId,
    UUID customerId,
    IdentitySubjectType actorType,
    ProvisionedIdentityStatus status
) {
    public ProvisionedCustomerIdentity {
        Objects.requireNonNull(identityId, "identityId is required.");
        Objects.requireNonNull(customerId, "customerId is required.");
        Objects.requireNonNull(actorType, "actorType is required.");
        Objects.requireNonNull(status, "status is required.");
    }

    @Override
    public String toString() {
        return "ProvisionedCustomerIdentity[identityId=redacted, customerId=redacted, actorType="
                + actorType + ", status=" + status + "]";
    }
}
