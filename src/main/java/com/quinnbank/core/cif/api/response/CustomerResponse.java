package com.quinnbank.core.cif.api.response;

import java.time.LocalDateTime;
import java.util.UUID;

import com.quinnbank.core.cif.application.result.CustomerSnapshot;
import com.quinnbank.core.cif.domain.enums.CustomerStatus;

public record CustomerResponse(
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
    public static CustomerResponse from(CustomerSnapshot customerSnapshot){
        return new CustomerResponse(
            customerSnapshot.id(),
            customerSnapshot.customerNumber(),
            customerSnapshot.firstName(),
            customerSnapshot.lastName(),
            customerSnapshot.email(),
            customerSnapshot.phone(),
            customerSnapshot.status(),
            customerSnapshot.createdAt(),
            customerSnapshot.updatedAt()
        );
    }
}
