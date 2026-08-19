package com.quinnbank.core.identity.infrastructure.security;

import com.quinnbank.core.identity.application.port.IdentityAccountRepository;
import com.quinnbank.core.identity.application.result.AuthenticatedSubject;
import com.quinnbank.core.identity.application.result.IdentitySubjectType;
import com.quinnbank.core.identity.domain.AuthenticationActor;
import com.quinnbank.core.identity.domain.EncodedPassword;
import com.quinnbank.core.identity.domain.IdentityAccount;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SpringSecurityAuthenticatedSubjectProviderTest {
    private static final Instant NOW = Instant.parse("2026-08-19T08:00:00Z");
    private static final UUID IDENTITY_ID = UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final UUID CUSTOMER_ID = UUID.fromString("20000000-0000-0000-0000-000000000002");

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void resolvesTheServerStoredCustomerSubjectFromTheJwtIdentityId() {
        IdentityAccount identity = activeIdentity();
        IdentityAccountRepository identities = mock(IdentityAccountRepository.class);
        when(identities.findById(IDENTITY_ID)).thenReturn(Optional.of(identity));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthentication(
            IDENTITY_ID,
            IdentityActorType.RETAIL_CUSTOMER
        ));

        Optional<AuthenticatedSubject> result = provider(identities).currentSubject();

        assertEquals(
            Optional.of(new AuthenticatedSubject(
                IDENTITY_ID,
                IdentitySubjectType.RETAIL_CUSTOMER,
                CUSTOMER_ID
            )),
            result
        );
    }

    @Test
    void failsClosedWhenTheTokenActorDoesNotMatchTheStoredIdentity() {
        IdentityAccountRepository identities = mock(IdentityAccountRepository.class);
        when(identities.findById(IDENTITY_ID)).thenReturn(Optional.of(activeIdentity()));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthentication(
            IDENTITY_ID,
            IdentityActorType.BUSINESS_CUSTOMER
        ));

        assertTrue(provider(identities).currentSubject().isEmpty());
    }

    @Test
    void failsClosedWhenTheStoredIdentityIsDisabled() {
        IdentityAccountRepository identities = mock(IdentityAccountRepository.class);
        when(identities.findById(IDENTITY_ID)).thenReturn(Optional.of(disabledIdentity()));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthentication(
            IDENTITY_ID.toString(),
            IdentityActorType.RETAIL_CUSTOMER
        ));

        assertTrue(provider(identities).currentSubject().isEmpty());
    }

    @Test
    void failsClosedWhenTheJwtSubjectIsMalformedOrMissingFromStorage() {
        IdentityAccountRepository identities = mock(IdentityAccountRepository.class);
        SecurityContextHolder.getContext().setAuthentication(jwtAuthentication(
            "not-a-uuid",
            IdentityActorType.RETAIL_CUSTOMER
        ));
        assertTrue(provider(identities).currentSubject().isEmpty());

        SecurityContextHolder.getContext().setAuthentication(jwtAuthentication(
            IDENTITY_ID.toString(),
            IdentityActorType.RETAIL_CUSTOMER
        ));
        when(identities.findById(IDENTITY_ID)).thenReturn(Optional.empty());
        assertTrue(provider(identities).currentSubject().isEmpty());
    }

    @Test
    void returnsNoSubjectWithoutAValidatedJwtAuthentication() {
        IdentityAccountRepository identities = mock(IdentityAccountRepository.class);

        assertTrue(provider(identities).currentSubject().isEmpty());
    }

    private static SpringSecurityAuthenticatedSubjectProvider provider(IdentityAccountRepository identities) {
        return new SpringSecurityAuthenticatedSubjectProvider(
            identities,
            Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    private static IdentityAccount activeIdentity() {
        IdentityAccount identity = disabledIdentity();
        identity.enable(
            AuthenticationActor.of(IdentityActorType.SERVICE_ACCOUNT, "synthetic-onboarding"),
            "subject-provider-test",
            NOW.minusSeconds(1)
        );
        identity.releaseAuditEvents();
        return identity;
    }

    private static IdentityAccount disabledIdentity() {
        AuthenticationActor provisioner = AuthenticationActor.of(
            IdentityActorType.SERVICE_ACCOUNT,
            "synthetic-onboarding"
        );
        IdentityAccount identity = IdentityAccount.provision(
            IDENTITY_ID,
            CUSTOMER_ID,
            IdentityActorType.RETAIL_CUSTOMER,
            "subject-provider@example.invalid",
            EncodedPassword.fromPasswordEncoder("$2b$12$" + "a".repeat(53)),
            provisioner,
            "subject-provider-test",
            NOW.minusSeconds(2)
        );
        identity.releaseAuditEvents();
        return identity;
    }

    private static JwtAuthenticationToken jwtAuthentication(
        UUID identityId,
        IdentityActorType actorType
    ) {
        return jwtAuthentication(identityId.toString(), actorType);
    }

    private static JwtAuthenticationToken jwtAuthentication(
        String identityId,
        IdentityActorType actorType
    ) {
        Jwt jwt = Jwt.withTokenValue("synthetic-access-token")
            .header("alg", "RS256")
            .subject(identityId)
            .issuedAt(NOW.minusSeconds(1))
            .expiresAt(NOW.plusSeconds(300))
            .claim(IdentityJwtClaimValidator.ACTOR_TYPE_CLAIM, actorType.name())
            .build();
        return new JwtAuthenticationToken(
            jwt,
            java.util.List.of(new SimpleGrantedAuthority("actor:" + actorType.name().toLowerCase()))
        );
    }
}
