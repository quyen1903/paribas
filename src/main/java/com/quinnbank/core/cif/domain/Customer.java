package com.quinnbank.core.cif.domain;

import com.quinnbank.core.cif.domain.enums.CustomerStatus;
import com.quinnbank.core.cif.domain.enums.RiskRating;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Locale;
import java.util.UUID;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "customers")
@Entity
@Getter
public class Customer {
    private static final int MAX_NAME_LENGTH = 100;
    private static final int MAX_EMAIL_LENGTH = 254;
    private static final int MAX_PHONE_LENGTH = 50;
    private static final int MAX_CUSTOMER_NUMBER_LENGTH = 50;

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    @Column(name = "customer_number", nullable = false, unique = true, length = 50)
    private String customerNumber;

    @Column(name = "first_name", nullable = false, length = 100)
    private String firstName;

    @Column(name = "last_name", nullable = false, length = 100)
    private String lastName;

    @Column(name = "email", nullable = false, unique = true, length = 254)
    private String email;

    @Column(name = "phone", nullable = false, length = 50)
    private String phone;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 50)
    private CustomerStatus status;

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_rating", nullable = false, length = 50)
    private RiskRating riskRating;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public static Customer register(
            UUID id,
            String customerNumber,
            String firstName,
            String lastName,
            String email,
            String phone,
            LocalDateTime now
    ) {
        requirePresent(id, "id");
        requirePresent(now, "now");

        Customer customer = new Customer();
        customer.id = id;
        customer.customerNumber = requireText(customerNumber, "customerNumber", MAX_CUSTOMER_NUMBER_LENGTH);
        customer.firstName = requireText(firstName, "firstName", MAX_NAME_LENGTH);
        customer.lastName = requireText(lastName, "lastName", MAX_NAME_LENGTH);
        customer.email = normalizeEmail(email);
        customer.phone = requireText(phone, "phone", MAX_PHONE_LENGTH);
        customer.status = CustomerStatus.ACTIVE;
        customer.riskRating = RiskRating.LOW;
        customer.createdAt = now;
        customer.updatedAt = now;
        return customer;
    }

    public void updateProfile(String firstName, String lastName, String email, String phone, LocalDateTime now) {
        requireOpenForProfileChange();
        requirePresent(now, "now");

        this.firstName = requireText(firstName, "firstName", MAX_NAME_LENGTH);
        this.lastName = requireText(lastName, "lastName", MAX_NAME_LENGTH);
        this.email = normalizeEmail(email);
        this.phone = requireText(phone, "phone", MAX_PHONE_LENGTH);
        this.updatedAt = now;
    }

    public void close(LocalDateTime now) {
        requirePresent(now, "now");
        if (status == CustomerStatus.CLOSED) {
            return;
        }

        this.status = CustomerStatus.CLOSED;
        this.updatedAt = now;
    }

    private void requireOpenForProfileChange() {
        if (status == CustomerStatus.CLOSED) {
            throw new IllegalStateException("Closed customer profiles cannot be updated.");
        }
    }

    private static String normalizeEmail(String value) {
        return requireText(value, "email", MAX_EMAIL_LENGTH).toLowerCase(Locale.ROOT);
    }

    private static String requireText(String value, String fieldName, int maxLength) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " is required.");
        }

        String trimmed = value.trim();
        if (trimmed.length() > maxLength) {
            throw new IllegalArgumentException(fieldName + " is too long.");
        }

        return trimmed;
    }

    private static void requirePresent(Object value, String fieldName) {
        if (value == null) {
            throw new IllegalArgumentException(fieldName + " is required.");
        }
    }
}
