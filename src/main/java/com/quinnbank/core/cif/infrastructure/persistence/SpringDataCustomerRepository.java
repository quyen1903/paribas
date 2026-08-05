package com.quinnbank.core.cif.infrastructure.persistence;

import com.quinnbank.core.cif.domain.Customer;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;


public interface SpringDataCustomerRepository extends JpaRepository<Customer, UUID> {
    boolean existsByEmail(String email);

    boolean existsByEmailAndIdNot(String email, UUID id);

    boolean existsByCustomerNumber(String customerNumber);

    Optional<Customer> findByCustomerNumber(String customerNumber);
}
