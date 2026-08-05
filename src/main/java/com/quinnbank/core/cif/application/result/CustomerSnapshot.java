package com.quinnbank.core.cif.application.result;

import com.quinnbank.core.cif.domain.Customer;
import com.quinnbank.core.cif.domain.enums.CustomerStatus;

import java.time.LocalDateTime;
import java.util.UUID;

public record CustomerSnapshot(
    UUID id,
    String customerNumber,
    String firstName,
    String lastName,
    String email,
    String phone,
    CustomerStatus status,
    LocalDateTime createdAt,
    LocalDateTime updatedAt
) {
    public static CustomerSnapshot from(Customer customer) {
        return new CustomerSnapshot(
            customer.getId(),
            customer.getCustomerNumber(),
            customer.getFirstName(),
            customer.getLastName(),
            customer.getEmail(),
            customer.getPhone(),
            customer.getStatus(),
            customer.getCreatedAt(),
            customer.getUpdatedAt()
        );
    }
}
