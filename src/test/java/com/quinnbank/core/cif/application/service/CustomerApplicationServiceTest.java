package com.quinnbank.core.cif.application.service;

import com.quinnbank.core.cif.application.command.RegisterCustomerCommand;
import com.quinnbank.core.cif.application.command.UpdateCustomerCommand;
import com.quinnbank.core.cif.application.port.out.CustomerRepositoryPort;
import com.quinnbank.core.cif.application.query.ListCustomersQuery;
import com.quinnbank.core.cif.application.result.CustomerPage;
import com.quinnbank.core.cif.application.result.CustomerSnapshot;
import com.quinnbank.core.cif.domain.Customer;
import com.quinnbank.core.cif.domain.enums.CustomerStatus;
import com.quinnbank.core.cif.domain.exception.CustomerClosedException;
import com.quinnbank.core.cif.domain.exception.DuplicateCustomerEmailException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CustomerApplicationServiceTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-07-09T08:00:00Z"), ZoneOffset.UTC);
    private static final LocalDateTime NOW = LocalDateTime.ofInstant(CLOCK.instant(), ZoneOffset.UTC);

    private InMemoryCustomerRepository repository;
    private CustomerApplicationService service;

    @BeforeEach
    void setUp() {
        repository = new InMemoryCustomerRepository();
        service = new CustomerApplicationService(repository, CLOCK);
    }

    @Test
    void registerCustomerCreatesCifWithGeneratedCustomerNumber() {
        CustomerSnapshot snapshot = service.registerCustomer(new RegisterCustomerCommand(
                "Quinn",
                "Nguyen",
                "QUINN@example.invalid",
                "+84901234567"
        ));

        assertNotNull(snapshot.id());
        assertEquals("quinn@example.invalid", snapshot.email());
        assertEquals("Quinn", snapshot.firstName());
        assertEquals(CustomerStatus.ACTIVE, snapshot.status());
        assertEquals(NOW, snapshot.createdAt());
        assertEquals("CIF" + snapshot.id().toString().replace("-", "").toUpperCase(), snapshot.customerNumber());
    }

    @Test
    void registerCustomerRejectsDuplicateEmail() {
        service.registerCustomer(new RegisterCustomerCommand("Quinn", "Nguyen", "quinn@example.invalid", "+84901234567"));

        assertThrows(
                DuplicateCustomerEmailException.class,
                () -> service.registerCustomer(new RegisterCustomerCommand("Other", "Person", "QUINN@example.invalid", "+84907654321"))
        );
    }

    @Test
    void updateCustomerProfileRejectsEmailOwnedByAnotherCustomer() {
        CustomerSnapshot first = service.registerCustomer(new RegisterCustomerCommand("Quinn", "Nguyen", "quinn@example.invalid", "+84901234567"));
        service.registerCustomer(new RegisterCustomerCommand("Anh", "Tran", "anh@example.invalid", "+84907654321"));

        assertThrows(
                DuplicateCustomerEmailException.class,
                () -> service.updateCustomerProfile(new UpdateCustomerCommand(
                        first.id(),
                        "Quinn",
                        "Nguyen",
                        "anh@example.invalid",
                        "+84901234567"
                ))
        );
    }

    @Test
    void closeCustomerSoftDeletesByChangingStatus() {
        CustomerSnapshot snapshot = service.registerCustomer(new RegisterCustomerCommand(
                "Quinn",
                "Nguyen",
                "quinn@example.invalid",
                "+84901234567"
        ));

        service.closeCustomer(snapshot.id());

        Customer closed = repository.findById(snapshot.id()).orElseThrow();
        assertEquals(CustomerStatus.CLOSED, closed.getStatus());
        assertThrows(
                CustomerClosedException.class,
                () -> service.updateCustomerProfile(new UpdateCustomerCommand(
                        snapshot.id(),
                        "Quinn",
                        "Nguyen",
                        "quinn2@example.invalid",
                        "+84901234567"
                ))
        );
    }

    @Test
    void listCustomersReturnsPagedResults() {
        service.registerCustomer(new RegisterCustomerCommand("One", "Customer", "one@example.invalid", "+84900000001"));
        service.registerCustomer(new RegisterCustomerCommand("Two", "Customer", "two@example.invalid", "+84900000002"));

        CustomerPage page = service.listCustomers(new ListCustomersQuery(0, 1));

        assertEquals(1, page.customers().size());
        assertEquals(0, page.page());
        assertEquals(1, page.size());
        assertEquals(2, page.totalElements());
    }

    private static final class InMemoryCustomerRepository implements CustomerRepositoryPort {
        private final Map<UUID, Customer> customers = new LinkedHashMap<>();

        @Override
        public Customer save(Customer customer) {
            customers.put(customer.getId(), customer);
            return customer;
        }

        @Override
        public Optional<Customer> findById(UUID customerId) {
            return Optional.ofNullable(customers.get(customerId));
        }

        @Override
        public Optional<Customer> findByIdForUpdate(UUID customerId) {
            return findById(customerId);
        }

        @Override
        public Optional<Customer> findByCustomerNumber(String customerNumber) {
            return customers.values()
                    .stream()
                    .filter(customer -> customer.getCustomerNumber().equals(customerNumber))
                    .findFirst();
        }

        @Override
        public boolean existsByEmail(String email) {
            return customers.values()
                    .stream()
                    .anyMatch(customer -> customer.getEmail().equals(email));
        }

        @Override
        public boolean existsByEmailForDifferentCustomer(String email, UUID customerId) {
            return customers.values()
                    .stream()
                    .anyMatch(customer -> customer.getEmail().equals(email) && !customer.getId().equals(customerId));
        }

        @Override
        public boolean existsByCustomerNumber(String customerNumber) {
            return customers.values()
                    .stream()
                    .anyMatch(customer -> customer.getCustomerNumber().equals(customerNumber));
        }

        @Override
        public List<Customer> findPage(int page, int size) {
            int start = page * size;
            return new ArrayList<>(customers.values())
                    .stream()
                    .skip(start)
                    .limit(size)
                    .toList();
        }

        @Override
        public long count() {
            return customers.size();
        }
    }
}
