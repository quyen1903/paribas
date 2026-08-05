package com.quinnbank.core.cif.application.service;

import com.quinnbank.core.cif.application.command.RegisterCustomerCommand;
import com.quinnbank.core.cif.application.command.UpdateCustomerCommand;
import com.quinnbank.core.cif.application.port.in.CloseCustomerUseCase;
import com.quinnbank.core.cif.application.port.in.GetCustomerUseCase;
import com.quinnbank.core.cif.application.port.in.ListCustomersUseCase;
import com.quinnbank.core.cif.application.port.in.RegisterCustomerUseCase;
import com.quinnbank.core.cif.application.port.in.UpdateCustomerProfileUseCase;
import com.quinnbank.core.cif.application.port.out.CustomerRepositoryPort;
import com.quinnbank.core.cif.application.query.ListCustomersQuery;
import com.quinnbank.core.cif.application.result.CustomerPage;
import com.quinnbank.core.cif.application.result.CustomerSnapshot;
import com.quinnbank.core.cif.domain.Customer;
import com.quinnbank.core.cif.domain.enums.CustomerStatus;
import com.quinnbank.core.cif.domain.exception.CustomerClosedException;
import com.quinnbank.core.cif.domain.exception.CustomerNotFoundException;
import com.quinnbank.core.cif.domain.exception.DuplicateCustomerEmailException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
@Transactional
public class CustomerApplicationService implements
        RegisterCustomerUseCase,
        UpdateCustomerProfileUseCase,
        CloseCustomerUseCase,
        GetCustomerUseCase,
        ListCustomersUseCase {
    private static final int MAX_PAGE_SIZE = 100;

    private final CustomerRepositoryPort customers;
    private final Clock clock;

    public CustomerApplicationService(CustomerRepositoryPort customers, Clock clock) {
        this.customers = customers;
        this.clock = clock;
    }

    @Override
    public CustomerSnapshot registerCustomer(RegisterCustomerCommand command) {
        String email = normalizeEmail(command.email());
        if (customers.existsByEmail(email)) {
            throw new DuplicateCustomerEmailException(email);
        }

        UUID customerId = UUID.randomUUID();
        Customer customer = Customer.register(
                customerId,
                customerNumberFrom(customerId),
                command.firstName(),
                command.lastName(),
                email,
                command.phone(),
                now()
        );

        return CustomerSnapshot.from(customers.save(customer));
    }

    @Override
    public CustomerSnapshot updateCustomerProfile(UpdateCustomerCommand command) {
        Customer customer = customers.findById(command.customerId())
                .orElseThrow(() -> new CustomerNotFoundException(command.customerId()));
        if (customer.getStatus() == CustomerStatus.CLOSED) {
            throw new CustomerClosedException(command.customerId());
        }

        String email = normalizeEmail(command.email());
        if (customers.existsByEmailForDifferentCustomer(email, command.customerId())) {
            throw new DuplicateCustomerEmailException(email);
        }

        customer.updateProfile(command.firstName(), command.lastName(), email, command.phone(), now());
        return CustomerSnapshot.from(customers.save(customer));
    }

    @Override
    public void closeCustomer(UUID customerId) {
        Customer customer = customers.findById(customerId)
                .orElseThrow(() -> new CustomerNotFoundException(customerId));

        customer.close(now());
        customers.save(customer);
    }

    @Override
    @Transactional(readOnly = true)
    public CustomerSnapshot getCustomer(UUID customerId) {
        return customers.findById(customerId)
                .map(CustomerSnapshot::from)
                .orElseThrow(() -> new CustomerNotFoundException(customerId));
    }

    @Override
    @Transactional(readOnly = true)
    public CustomerSnapshot getCustomerByNumber(String customerNumber) {
        return customers.findByCustomerNumber(customerNumber)
                .map(CustomerSnapshot::from)
                .orElseThrow(() -> new CustomerNotFoundException(customerNumber));
    }

    @Override
    @Transactional(readOnly = true)
    public CustomerPage listCustomers(ListCustomersQuery query) {
        validatePage(query);

        List<CustomerSnapshot> snapshots = customers.findPage(query.page(), query.size())
                .stream()
                .map(CustomerSnapshot::from)
                .toList();

        return new CustomerPage(snapshots, query.page(), query.size(), customers.count());
    }

    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }

    private static void validatePage(ListCustomersQuery query) {
        if (query.page() < 0) {
            throw new IllegalArgumentException("page must not be negative.");
        }

        if (query.size() < 1 || query.size() > MAX_PAGE_SIZE) {
            throw new IllegalArgumentException("size must be between 1 and 100.");
        }
    }

    private static String normalizeEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("email is required.");
        }

        return email.trim().toLowerCase(Locale.ROOT);
    }

    private static String customerNumberFrom(UUID customerId) {
        return "CIF" + customerId.toString().replace("-", "").toUpperCase(Locale.ROOT);
    }
}
