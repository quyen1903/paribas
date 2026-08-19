package com.quinnbank.core.identity.infrastructure.security;

import com.quinnbank.core.identity.application.port.AuthenticatedSubjectProvider;
import com.quinnbank.core.identity.application.port.IdentityAccountRepository;
import com.quinnbank.core.identity.application.result.AuthenticatedSubject;
import com.quinnbank.core.identity.application.result.IdentitySubjectType;
import com.quinnbank.core.identity.domain.IdentityAccount;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.Optional;
import java.util.UUID;

@Component
public class SpringSecurityAuthenticatedSubjectProvider implements AuthenticatedSubjectProvider {
    private final IdentityAccountRepository identityAccounts;
    private final Clock clock;

    public SpringSecurityAuthenticatedSubjectProvider(
        IdentityAccountRepository identityAccounts,
        Clock clock
    ) {
        this.identityAccounts = identityAccounts;
        this.clock = clock;
    }

    @Override
    public Optional<AuthenticatedSubject> currentSubject() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof JwtAuthenticationToken jwtAuthentication)
                || !authentication.isAuthenticated()) {
            return Optional.empty();
        }

        try {
            UUID identityId = UUID.fromString(jwtAuthentication.getToken().getSubject());
            IdentityActorType claimedActorType = IdentityActorType.valueOf(
                jwtAuthentication.getToken().getClaimAsString(IdentityJwtClaimValidator.ACTOR_TYPE_CLAIM)
            );
            IdentityAccount identity = identityAccounts.findById(identityId).orElse(null);
            if (identity == null
                    || identity.getActorType() != claimedActorType
                    || !identity.canAuthenticate(clock.instant())) {
                return Optional.empty();
            }
            return Optional.of(new AuthenticatedSubject(
                identity.getId(),
                toContractType(identity.getActorType()),
                identity.getSubjectId()
            ));
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    private static IdentitySubjectType toContractType(IdentityActorType actorType) {
        return switch (actorType) {
            case RETAIL_CUSTOMER -> IdentitySubjectType.RETAIL_CUSTOMER;
            case BUSINESS_CUSTOMER -> IdentitySubjectType.BUSINESS_CUSTOMER;
            case BANK_EMPLOYEE -> IdentitySubjectType.BANK_EMPLOYEE;
            case BACK_OFFICE_OPERATOR -> IdentitySubjectType.BACK_OFFICE_OPERATOR;
            case SERVICE_ACCOUNT -> IdentitySubjectType.SERVICE_ACCOUNT;
            case THIRD_PARTY_PARTNER -> IdentitySubjectType.THIRD_PARTY_PARTNER;
            case BATCH_JOB -> IdentitySubjectType.BATCH_JOB;
        };
    }
}
