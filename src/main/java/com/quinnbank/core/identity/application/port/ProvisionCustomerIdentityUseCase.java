package com.quinnbank.core.identity.application.port;

import com.quinnbank.core.identity.application.command.ProvisionCustomerIdentityCommand;
import com.quinnbank.core.identity.application.result.ProvisionedCustomerIdentity;

/**
 * Stable cross-module contract for a trusted CIF/onboarding coordinator.
 * This contract is intentionally not exposed as a public identity endpoint.
 */
public interface ProvisionCustomerIdentityUseCase {
    ProvisionedCustomerIdentity provision(ProvisionCustomerIdentityCommand command);
}
