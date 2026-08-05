package com.quinnbank.core.cif.domain;

import com.quinnbank.core.cif.domain.enums.CustomerStatus;
import com.quinnbank.core.cif.domain.enums.RiskRating;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CustomerTest {
    private static final LocalDateTime CREATED_AT = LocalDateTime.of(2026, 7, 9, 8, 0);

    @Test
    void registerCreatesCustomerWithDefaultCifState() {
        UUID id = UUID.randomUUID();

        Customer customer = Customer.register(
                id,
                "CIF123",
                "Quinn",
                "Nguyen",
                "QUINN@example.invalid",
                "+84901234567",
                CREATED_AT
        );

        assertEquals(id, customer.getId());
        assertEquals("CIF123", customer.getCustomerNumber());
        assertEquals("quinn@example.invalid", customer.getEmail());
        assertEquals(CustomerStatus.ACTIVE, customer.getStatus());
        assertEquals(RiskRating.LOW, customer.getRiskRating());
        assertEquals(CREATED_AT, customer.getCreatedAt());
        assertEquals(CREATED_AT, customer.getUpdatedAt());
    }

    @Test
    void updateProfileChangesProfileFieldsAndTimestamp() {
        Customer customer = newCustomer();
        LocalDateTime updatedAt = CREATED_AT.plusHours(1);

        customer.updateProfile("Anh", "Tran", "ANH@example.invalid", "+84907654321", updatedAt);

        assertEquals("Anh", customer.getFirstName());
        assertEquals("Tran", customer.getLastName());
        assertEquals("anh@example.invalid", customer.getEmail());
        assertEquals("+84907654321", customer.getPhone());
        assertEquals(updatedAt, customer.getUpdatedAt());
    }

    @Test
    void closedCustomerProfileCannotBeUpdated() {
        Customer customer = newCustomer();
        customer.close(CREATED_AT.plusMinutes(10));

        assertThrows(
                IllegalStateException.class,
                () -> customer.updateProfile("Anh", "Tran", "anh@example.invalid", "+84907654321", CREATED_AT.plusHours(1))
        );
    }

    private static Customer newCustomer() {
        return Customer.register(
            UUID.randomUUID(),
            "CIF123",
            "Quinn",
            "Nguyen",
            "quinn@example.invalid",
            "+84901234567",
            CREATED_AT
        );
    }
}
