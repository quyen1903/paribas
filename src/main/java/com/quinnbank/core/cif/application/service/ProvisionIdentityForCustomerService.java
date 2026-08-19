package com.quinnbank.core.cif.application.service;

import com.quinnbank.core.cif.application.command.ProvisionIdentityForCustomerCommand;
import com.quinnbank.core.cif.application.exception.CustomerIdentityProvisioningRejectedException;
import com.quinnbank.core.cif.application.port.out.CustomerRepositoryPort;
import com.quinnbank.core.cif.domain.Customer;
import com.quinnbank.core.cif.domain.enums.CustomerStatus;
import com.quinnbank.core.cif.domain.exception.CustomerNotFoundException;
import com.quinnbank.core.identity.application.command.ProvisionCustomerIdentityCommand;
import com.quinnbank.core.identity.application.port.ProvisionCustomerIdentityUseCase;
import com.quinnbank.core.identity.application.result.ProvisionedCustomerIdentity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ProvisionIdentityForCustomerService {
    private final CustomerRepositoryPort customers;
    private final ProvisionCustomerIdentityUseCase customerIdentities;

    public ProvisionIdentityForCustomerService(
        CustomerRepositoryPort customers,
        ProvisionCustomerIdentityUseCase customerIdentities
    ) {
        this.customers = customers;
        this.customerIdentities = customerIdentities;
    }

    @Transactional
    public ProvisionedCustomerIdentity provision(ProvisionIdentityForCustomerCommand command) {
        Customer customer = customers.findByIdForUpdate(command.customerId())
            .orElseThrow(() -> new CustomerNotFoundException(command.customerId()));
        if (customer.getStatus() != CustomerStatus.ACTIVE) {
            throw new CustomerIdentityProvisioningRejectedException();
        }

        return customerIdentities.provision(new ProvisionCustomerIdentityCommand(
            customer.getId(),
            customer.getEmail(),
            command.correlationId(),
            command.sourceAddress()
        ));
    }
}
