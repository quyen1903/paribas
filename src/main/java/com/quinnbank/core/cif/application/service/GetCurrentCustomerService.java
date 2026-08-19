package com.quinnbank.core.cif.application.service;

import com.quinnbank.core.cif.application.exception.CustomerAccessDeniedException;
import com.quinnbank.core.cif.application.port.out.CustomerRepositoryPort;
import com.quinnbank.core.cif.application.result.CustomerSnapshot;
import com.quinnbank.core.identity.application.port.AuthenticatedSubjectProvider;
import com.quinnbank.core.identity.application.port.AuthorizationDenialAudit;
import com.quinnbank.core.identity.application.result.AuthenticatedSubject;
import com.quinnbank.core.identity.application.result.IdentitySubjectType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.regex.Pattern;

@Service
public class GetCurrentCustomerService {
    private static final Pattern CORRELATION_ID_PATTERN =
        Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,63}");

    private final CustomerRepositoryPort customers;
    private final AuthenticatedSubjectProvider authenticatedSubjects;
    private final AuthorizationDenialAudit authorizationDenials;

    public GetCurrentCustomerService(
        CustomerRepositoryPort customers,
        AuthenticatedSubjectProvider authenticatedSubjects,
        AuthorizationDenialAudit authorizationDenials
    ) {
        this.customers = customers;
        this.authenticatedSubjects = authenticatedSubjects;
        this.authorizationDenials = authorizationDenials;
    }

    @Transactional(readOnly = true)
    public CustomerSnapshot getCurrentCustomer(String correlationId) {
        String validatedCorrelationId = requireCorrelationId(correlationId);
        Optional<AuthenticatedSubject> resolvedActor = authenticatedSubjects.currentSubject();
        if (resolvedActor.isEmpty()) {
            authorizationDenials.recordAnonymous(
                IdentitySubjectType.RETAIL_CUSTOMER,
                "CUSTOMER_SUBJECT_UNAVAILABLE",
                validatedCorrelationId
            );
            throw new CustomerAccessDeniedException();
        }

        AuthenticatedSubject actor = resolvedActor.orElseThrow();
        if (actor.actorType() != IdentitySubjectType.RETAIL_CUSTOMER) {
            authorizationDenials.recordKnown(
                actor.identityId(),
                actor.actorType(),
                "CUSTOMER_ACTOR_SCOPE_DENIED",
                validatedCorrelationId
            );
            throw new CustomerAccessDeniedException();
        }

        Optional<CustomerSnapshot> customer = customers.findById(actor.subjectId())
            .map(CustomerSnapshot::from);
        if (customer.isEmpty()) {
            authorizationDenials.recordKnown(
                actor.identityId(),
                actor.actorType(),
                "CUSTOMER_BINDING_NOT_FOUND",
                validatedCorrelationId
            );
            throw new CustomerAccessDeniedException();
        }
        return customer.orElseThrow();
    }

    private static String requireCorrelationId(String correlationId) {
        if (correlationId == null || !CORRELATION_ID_PATTERN.matcher(correlationId).matches()) {
            throw new IllegalArgumentException("correlationId is invalid.");
        }
        return correlationId;
    }
}
