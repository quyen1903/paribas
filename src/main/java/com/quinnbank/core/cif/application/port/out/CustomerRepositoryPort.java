package com.quinnbank.core.cif.application.port.out;

import com.quinnbank.core.cif.domain.Customer;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface CustomerRepositoryPort {
    Customer save(Customer customer);

    Optional<Customer> findById(UUID customerId);

    Optional<Customer> findByCustomerNumber(String customerNumber);

    boolean existsByEmail(String email);

    boolean existsByEmailForDifferentCustomer(String email, UUID customerId);

    boolean existsByCustomerNumber(String customerNumber);

    List<Customer> findPage(int page, int size);

    long count();
}
