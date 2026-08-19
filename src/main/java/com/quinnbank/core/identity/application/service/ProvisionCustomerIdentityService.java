package com.quinnbank.core.identity.application.service;

import com.quinnbank.core.identity.application.command.ProvisionCustomerIdentityCommand;
import com.quinnbank.core.identity.application.exception.IdentityProvisioningConflictException;
import com.quinnbank.core.identity.application.exception.InvalidIdentityProvisioningException;
import com.quinnbank.core.identity.application.policy.AuthenticationTimestampPolicy;
import com.quinnbank.core.identity.application.port.AuthenticationAuditRepository;
import com.quinnbank.core.identity.application.port.AuthenticationThrottle;
import com.quinnbank.core.identity.application.port.IdentityAccountRepository;
import com.quinnbank.core.identity.application.port.PasswordService;
import com.quinnbank.core.identity.application.port.ProvisionCustomerIdentityUseCase;
import com.quinnbank.core.identity.application.result.IdentitySubjectType;
import com.quinnbank.core.identity.application.result.ProvisionedIdentityStatus;
import com.quinnbank.core.identity.application.result.ProvisionedCustomerIdentity;
import com.quinnbank.core.identity.domain.AuthenticationActor;
import com.quinnbank.core.identity.domain.IdentityAccount;
import com.quinnbank.core.identity.domain.enums.IdentityAccountStatus;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

@Service
public class ProvisionCustomerIdentityService implements ProvisionCustomerIdentityUseCase {
    private static final AuthenticationActor CIF_ONBOARDING_SERVICE = AuthenticationActor.of(
        IdentityActorType.SERVICE_ACCOUNT,
        "cif-onboarding"
    );

    private final IdentityAccountRepository identityAccounts;
    private final AuthenticationAuditRepository audits;
    private final PasswordService passwords;
    private final AuthenticationThrottle throttle;
    private final Clock clock;

    public ProvisionCustomerIdentityService(
        IdentityAccountRepository identityAccounts,
        AuthenticationAuditRepository audits,
        PasswordService passwords,
        AuthenticationThrottle throttle,
        Clock clock
    ) {
        this.identityAccounts = identityAccounts;
        this.audits = audits;
        this.passwords = passwords;
        this.throttle = throttle;
        this.clock = clock;
    }

    @Override
    @Transactional
    public ProvisionedCustomerIdentity provision(ProvisionCustomerIdentityCommand command) {
        Instant now = AuthenticationTimestampPolicy.jwtCompatible(clock.instant());
        throttle.checkRegistration(command.sourceAddress(), now);

        String loginIdentifier;
        try {
            loginIdentifier = IdentityAccount.normalizeLoginIdentifier(command.loginIdentifier());
        } catch (IllegalArgumentException exception) {
            throw new InvalidIdentityProvisioningException();
        }

        IdentityAccount existingSubject = identityAccounts
            .findByActorTypeAndSubjectIdForUpdate(IdentityActorType.RETAIL_CUSTOMER, command.customerId())
            .orElse(null);
        if (existingSubject != null) {
            return exactReplay(existingSubject, loginIdentifier);
        }
        if (identityAccounts.existsByLoginIdentifier(loginIdentifier)) {
            throw new IdentityProvisioningConflictException();
        }

        IdentityAccount identity = IdentityAccount.provision(
            UUID.randomUUID(),
            command.customerId(),
            IdentityActorType.RETAIL_CUSTOMER,
            loginIdentifier,
            passwords.createUnusableCredential(),
            CIF_ONBOARDING_SERVICE,
            command.correlationId(),
            now
        );
        identityAccounts.save(identity);
        audits.saveAll(identity.releaseAuditEvents());
        return toResult(identity);
    }

    private ProvisionedCustomerIdentity exactReplay(
        IdentityAccount existing,
        String loginIdentifier
    ) {
        if (existing.getStatus() != IdentityAccountStatus.DISABLED
                || !existing.getLoginIdentifier().equals(loginIdentifier)) {
            throw new IdentityProvisioningConflictException();
        }
        return toResult(existing);
    }

    private static ProvisionedCustomerIdentity toResult(IdentityAccount identity) {
        IdentitySubjectType actorType = switch (identity.getActorType()) {
            case RETAIL_CUSTOMER -> IdentitySubjectType.RETAIL_CUSTOMER;
            case BUSINESS_CUSTOMER -> IdentitySubjectType.BUSINESS_CUSTOMER;
            case BANK_EMPLOYEE -> IdentitySubjectType.BANK_EMPLOYEE;
            case BACK_OFFICE_OPERATOR -> IdentitySubjectType.BACK_OFFICE_OPERATOR;
            case SERVICE_ACCOUNT -> IdentitySubjectType.SERVICE_ACCOUNT;
            case THIRD_PARTY_PARTNER -> IdentitySubjectType.THIRD_PARTY_PARTNER;
            case BATCH_JOB -> IdentitySubjectType.BATCH_JOB;
        };
        ProvisionedIdentityStatus status = switch (identity.getStatus()) {
            case ACTIVE -> ProvisionedIdentityStatus.ACTIVE;
            case DISABLED -> ProvisionedIdentityStatus.DISABLED;
            case CLOSED -> ProvisionedIdentityStatus.CLOSED;
        };
        return new ProvisionedCustomerIdentity(
            identity.getId(),
            identity.getSubjectId(),
            actorType,
            status
        );
    }
}
