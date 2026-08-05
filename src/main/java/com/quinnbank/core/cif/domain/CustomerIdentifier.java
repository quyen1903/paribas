package com.quinnbank.core.cif.domain;

import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

import com.quinnbank.core.cif.domain.enums.IdentifierStatus;
import com.quinnbank.core.cif.domain.enums.IdentifierType;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(
    name = "customer_identifier",
    uniqueConstraints = {
        @UniqueConstraint(
            name = "uk_customer_identifier_type_number",
            columnNames = {
                "document_type",
                "document_number"
            }
        )
    }
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
public class CustomerIdentifier {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
        name = "customer_id",
        nullable = false,
        updatable = false
    )
    private Customer customer;

    @Enumerated(EnumType.STRING)
    @Column(
        name = "document_type",
        nullable = false,
        length = 30
    )
    private IdentifierType documentType;

    @Column(
        name = "document_number",
        nullable = false,
        length = 100
    )
    private String documentNumber;

    @Enumerated(EnumType.STRING)
    @Column(
        name = "status",
        nullable = false,
        length = 30
    )
    private IdentifierStatus status;

    @Column(name = "status_reason", length = 500)
    private String statusReason;

    @Column(name = "issued_at")
    private LocalDate issuedAt;

    @Column(name = "expires_at")
    private LocalDate expiresAt;

    @Column(name = "verified_at")
    private Instant verifiedAt;

    @Column(name = "verified_by")
    private Long verifiedBy;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    private CustomerIdentifier(
            Customer customer,
            IdentifierType documentType,
            String documentNumber,
            LocalDate issuedAt,
            LocalDate expiresAt
    ) {
        if (customer == null) {
            throw new IllegalArgumentException("Customer is required");
        }

        if (documentType == null) {
            throw new IllegalArgumentException("Document type is required");
        }

        if (documentNumber == null || documentNumber.isBlank()) {
            throw new IllegalArgumentException("Document number is required");
        }

        if (issuedAt != null
                && expiresAt != null
                && expiresAt.isBefore(issuedAt)) {
            throw new IllegalArgumentException(
                    "Expiry date cannot be before issue date"
            );
        }

        this.customer = customer;
        this.documentType = documentType;
        this.documentNumber = documentNumber.trim();
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.status = IdentifierStatus.PENDING;
    }

    public static CustomerIdentifier pending(
            Customer customer,
            IdentifierType documentType,
            String documentNumber,
            LocalDate issuedAt,
            LocalDate expiresAt
    ) {
        return new CustomerIdentifier(
                customer,
                documentType,
                documentNumber,
                issuedAt,
                expiresAt
        );
    }

    public void verify(Long verifiedBy, Instant verifiedAt) {
        if (status != IdentifierStatus.PENDING) {
            throw new IllegalStateException(
                    "Only pending identifiers can be verified"
            );
        }

        this.status = IdentifierStatus.VERIFIED;
        this.verifiedBy = verifiedBy;
        this.verifiedAt = verifiedAt;
        this.statusReason = null;
    }

    public void reject(String reason) {
        if (status != IdentifierStatus.PENDING) {
            throw new IllegalStateException(
                    "Only pending identifiers can be rejected"
            );
        }

        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException(
                    "Rejection reason is required"
            );
        }

        this.status = IdentifierStatus.REJECTED;
        this.statusReason = reason.trim();
    }
}
