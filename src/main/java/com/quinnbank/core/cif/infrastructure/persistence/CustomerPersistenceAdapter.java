package com.quinnbank.core.cif.infrastructure.persistence;

import com.quinnbank.core.cif.application.port.out.CustomerRepositoryPort;
import com.quinnbank.core.cif.domain.Customer;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public class CustomerPersistenceAdapter implements CustomerRepositoryPort {
    private final SpringDataCustomerRepository repository;

    public CustomerPersistenceAdapter(SpringDataCustomerRepository repository) {
        this.repository = repository;
    }

    @Override
    public Customer save(Customer customer) {
        return repository.save(customer);
    }

    @Override
    public Optional<Customer> findById(UUID customerId) {
        return repository.findById(customerId);
    }

    @Override
    public Optional<Customer> findByIdForUpdate(UUID customerId) {
        return repository.findByIdForUpdate(customerId);
    }

    @Override
    public Optional<Customer> findByCustomerNumber(String customerNumber) {
        return repository.findByCustomerNumber(customerNumber);
    }

    @Override
    public boolean existsByEmail(String email) {
        return repository.existsByEmail(email);
    }

    @Override
    public boolean existsByEmailForDifferentCustomer(String email, UUID customerId) {
        return repository.existsByEmailAndIdNot(email, customerId);
    }

    @Override
    public boolean existsByCustomerNumber(String customerNumber) {
        return repository.existsByCustomerNumber(customerNumber);
    }

    @Override
    public List<Customer> findPage(int page, int size) {
        return repository.findAll(PageRequest.of(page, size)).getContent();
    }

    @Override
    public long count() {
        return repository.count();
    }
}
