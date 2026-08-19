package com.quinnbank.core.cif.application.service;

import com.quinnbank.core.cif.application.command.ProvisionIdentityForCustomerCommand;
import com.quinnbank.core.cif.application.exception.CustomerIdentityProvisioningRejectedException;
import com.quinnbank.core.cif.application.port.out.CustomerRepositoryPort;
import com.quinnbank.core.cif.domain.Customer;
import com.quinnbank.core.identity.application.command.ProvisionCustomerIdentityCommand;
import com.quinnbank.core.identity.application.port.ProvisionCustomerIdentityUseCase;
import com.quinnbank.core.identity.application.result.IdentitySubjectType;
import com.quinnbank.core.identity.application.result.ProvisionedIdentityStatus;
import com.quinnbank.core.identity.application.result.ProvisionedCustomerIdentity;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ProvisionIdentityForCustomerServiceTest {
    private static final UUID CUSTOMER_ID = UUID.fromString("20000000-0000-0000-0000-000000000002");
    private static final UUID IDENTITY_ID = UUID.fromString("10000000-0000-0000-0000-000000000001");
    @Test
    void passesTheServerLoadedCustomerIdAndEmailToTheIdentityContract() {
        Customer customer = activeCustomer();
        CustomerRepositoryPort customers = mock(CustomerRepositoryPort.class);
        ProvisionCustomerIdentityUseCase identities = mock(ProvisionCustomerIdentityUseCase.class);
        when(customers.findByIdForUpdate(CUSTOMER_ID)).thenReturn(Optional.of(customer));
        when(identities.provision(org.mockito.ArgumentMatchers.any())).thenReturn(
            new ProvisionedCustomerIdentity(
                IDENTITY_ID,
                CUSTOMER_ID,
                IdentitySubjectType.RETAIL_CUSTOMER,
                ProvisionedIdentityStatus.DISABLED
            )
        );
        ProvisionIdentityForCustomerCommand command = command();

        ProvisionedCustomerIdentity result = new ProvisionIdentityForCustomerService(
            customers,
            identities
        ).provision(command);

        ArgumentCaptor<ProvisionCustomerIdentityCommand> captured = ArgumentCaptor.forClass(
            ProvisionCustomerIdentityCommand.class
        );
        verify(identities).provision(captured.capture());
        verify(customers).findByIdForUpdate(CUSTOMER_ID);
        assertAll(
            () -> assertEquals(IDENTITY_ID, result.identityId()),
            () -> assertEquals(CUSTOMER_ID, captured.getValue().customerId()),
            () -> assertEquals("provisioned-customer@example.invalid", captured.getValue().loginIdentifier()),
            () -> assertFalse(command.toString().contains(CUSTOMER_ID.toString()))
        );
    }

    @Test
    void rejectsAClosedCustomerBeforeCallingIdentity() {
        Customer customer = activeCustomer();
        customer.close(LocalDateTime.parse("2026-08-19T08:01:00"));
        CustomerRepositoryPort customers = mock(CustomerRepositoryPort.class);
        ProvisionCustomerIdentityUseCase identities = mock(ProvisionCustomerIdentityUseCase.class);
        when(customers.findByIdForUpdate(CUSTOMER_ID)).thenReturn(Optional.of(customer));

        assertThrows(
            CustomerIdentityProvisioningRejectedException.class,
            () -> new ProvisionIdentityForCustomerService(customers, identities).provision(command())
        );
        verify(identities, never()).provision(org.mockito.ArgumentMatchers.any());
    }

    private static ProvisionIdentityForCustomerCommand command() {
        return new ProvisionIdentityForCustomerCommand(
            CUSTOMER_ID,
            "customer-identity-provisioning-test",
            "192.0.2.50"
        );
    }

    private static Customer activeCustomer() {
        return Customer.register(
            CUSTOMER_ID,
            "CIF20000000000000000000000000000002",
            "Provisioned",
            "Customer",
            "provisioned-customer@example.invalid",
            "+1-555-0101",
            LocalDateTime.parse("2026-08-19T08:00:00")
        );
    }
}
