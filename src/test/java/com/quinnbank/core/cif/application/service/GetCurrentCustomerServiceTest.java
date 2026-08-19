package com.quinnbank.core.cif.application.service;

import com.quinnbank.core.cif.application.exception.CustomerAccessDeniedException;
import com.quinnbank.core.cif.application.port.out.CustomerRepositoryPort;
import com.quinnbank.core.cif.application.result.CustomerSnapshot;
import com.quinnbank.core.cif.domain.Customer;
import com.quinnbank.core.identity.application.port.AuthenticatedSubjectProvider;
import com.quinnbank.core.identity.application.port.AuthorizationDenialAudit;
import com.quinnbank.core.identity.application.result.AuthenticatedSubject;
import com.quinnbank.core.identity.application.result.IdentitySubjectType;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GetCurrentCustomerServiceTest {
    private static final String CORRELATION_ID = "current-customer-test";
    private static final UUID IDENTITY_ID = UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final UUID CUSTOMER_ID = UUID.fromString("20000000-0000-0000-0000-000000000002");

    @Test
    void scopesTheReadToTheCustomerIdStoredOnTheAuthenticatedIdentity() {
        Customer customer = customer(CUSTOMER_ID);
        CustomerRepositoryPort customers = mock(CustomerRepositoryPort.class);
        AuthenticatedSubjectProvider subjects = mock(AuthenticatedSubjectProvider.class);
        AuthorizationDenialAudit denials = mock(AuthorizationDenialAudit.class);
        when(subjects.currentSubject()).thenReturn(Optional.of(new AuthenticatedSubject(
            IDENTITY_ID,
            IdentitySubjectType.RETAIL_CUSTOMER,
            CUSTOMER_ID
        )));
        when(customers.findById(CUSTOMER_ID)).thenReturn(Optional.of(customer));

        CustomerSnapshot result = new GetCurrentCustomerService(customers, subjects, denials)
            .getCurrentCustomer(CORRELATION_ID);

        assertEquals(CUSTOMER_ID, result.id());
        verify(customers).findById(CUSTOMER_ID);
        verify(denials, never()).recordKnown(
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any()
        );
    }

    @Test
    void deniesNonCustomerActorsBeforeReadingAnyCustomerProfile() {
        CustomerRepositoryPort customers = mock(CustomerRepositoryPort.class);
        AuthenticatedSubjectProvider subjects = mock(AuthenticatedSubjectProvider.class);
        AuthorizationDenialAudit denials = mock(AuthorizationDenialAudit.class);
        when(subjects.currentSubject()).thenReturn(Optional.of(new AuthenticatedSubject(
            IDENTITY_ID,
            IdentitySubjectType.BANK_EMPLOYEE,
            CUSTOMER_ID
        )));

        assertThrows(
            CustomerAccessDeniedException.class,
            () -> new GetCurrentCustomerService(customers, subjects, denials)
                .getCurrentCustomer(CORRELATION_ID)
        );
        verify(customers, never()).findById(CUSTOMER_ID);
        verify(denials).recordKnown(
            IDENTITY_ID,
            IdentitySubjectType.BANK_EMPLOYEE,
            "CUSTOMER_ACTOR_SCOPE_DENIED",
            CORRELATION_ID
        );
    }

    @Test
    void missingAuthenticatedSubjectUsesTheSafeDenial() {
        CustomerRepositoryPort customers = mock(CustomerRepositoryPort.class);
        AuthenticatedSubjectProvider subjects = mock(AuthenticatedSubjectProvider.class);
        AuthorizationDenialAudit denials = mock(AuthorizationDenialAudit.class);
        when(subjects.currentSubject()).thenReturn(Optional.empty());

        assertThrows(
            CustomerAccessDeniedException.class,
            () -> new GetCurrentCustomerService(customers, subjects, denials)
                .getCurrentCustomer(CORRELATION_ID)
        );
        verify(denials).recordAnonymous(
            IdentitySubjectType.RETAIL_CUSTOMER,
            "CUSTOMER_SUBJECT_UNAVAILABLE",
            CORRELATION_ID
        );
    }

    @Test
    void missingCustomerUsesTheSameSafeDenialWithoutChangingTheLookupScope() {
        CustomerRepositoryPort customers = mock(CustomerRepositoryPort.class);
        AuthenticatedSubjectProvider subjects = mock(AuthenticatedSubjectProvider.class);
        AuthorizationDenialAudit denials = mock(AuthorizationDenialAudit.class);
        when(subjects.currentSubject()).thenReturn(Optional.of(new AuthenticatedSubject(
            IDENTITY_ID,
            IdentitySubjectType.RETAIL_CUSTOMER,
            CUSTOMER_ID
        )));
        when(customers.findById(CUSTOMER_ID)).thenReturn(Optional.empty());

        assertThrows(
            CustomerAccessDeniedException.class,
            () -> new GetCurrentCustomerService(customers, subjects, denials)
                .getCurrentCustomer(CORRELATION_ID)
        );
        verify(customers).findById(CUSTOMER_ID);
        verify(denials).recordKnown(
            IDENTITY_ID,
            IdentitySubjectType.RETAIL_CUSTOMER,
            "CUSTOMER_BINDING_NOT_FOUND",
            CORRELATION_ID
        );
    }

    private static Customer customer(UUID customerId) {
        return Customer.register(
            customerId,
            "CIF" + customerId.toString().replace("-", "").toUpperCase(),
            "Synthetic",
            "Customer",
            "current-customer@example.invalid",
            "+1-555-0100",
            LocalDateTime.parse("2026-08-19T08:00:00")
        );
    }
}
