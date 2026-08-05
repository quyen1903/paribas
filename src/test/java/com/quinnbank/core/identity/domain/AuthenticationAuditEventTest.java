package com.quinnbank.core.identity.domain;

import com.quinnbank.core.identity.domain.enums.AuthenticationAction;
import com.quinnbank.core.identity.domain.enums.AuthenticationDecision;
import com.quinnbank.core.identity.domain.enums.AuthenticationMethod;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthenticationAuditEventTest {
    private static final UUID IDENTITY_ID = UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final Instant OCCURRED_AT = Instant.parse("2026-08-04T00:00:00Z");

    @Test
    void knownIdentityFactoryRetainsOnlyValidatedAuditFields() {
        AuthenticationActor actor = AuthenticationActor.of(
                IdentityActorType.RETAIL_CUSTOMER,
                "synthetic-subject-id"
        );

        AuthenticationAuditEvent event = AuthenticationAuditEvent.recordForKnownIdentity(
                IDENTITY_ID,
                actor,
                AuthenticationAction.TOKEN_PAIR_ISSUED,
                AuthenticationDecision.SUCCESS,
                AuthenticationMethod.JWT,
                "TOKENS_ISSUED",
                "known-correlation",
                OCCURRED_AT
        );

        assertAll(
                () -> assertEquals(IDENTITY_ID, event.getTargetIdentityId()),
                () -> assertEquals(actor.type(), event.getActorType()),
                () -> assertEquals(actor.id(), event.getActorId()),
                () -> assertEquals(AuthenticationAction.TOKEN_PAIR_ISSUED, event.getAction()),
                () -> assertEquals(AuthenticationMethod.JWT, event.getAuthenticationMethod()),
                () -> assertFalse(event.toString().contains(actor.id())),
                () -> assertFalse(event.toString().contains(event.getCorrelationId()))
        );
    }

    @Test
    void anonymousFactoryNeverAcceptsOrStoresSubmittedLoginIdentifier() {
        AuthenticationAuditEvent event = AuthenticationAuditEvent.recordAnonymous(
                IdentityActorType.RETAIL_CUSTOMER,
                AuthenticationAction.REGISTRATION_REJECTED,
                AuthenticationDecision.FAILURE,
                AuthenticationMethod.PASSWORD,
                "LOGIN_IDENTIFIER_UNAVAILABLE",
                "anonymous-correlation",
                OCCURRED_AT
        );

        assertAll(
                () -> assertNull(event.getTargetIdentityId()),
                () -> assertEquals("ANONYMOUS", event.getActorId()),
                () -> assertEquals(IdentityActorType.RETAIL_CUSTOMER, event.getActorType()),
                () -> assertEquals(AuthenticationAction.REGISTRATION_REJECTED, event.getAction())
        );
    }

    @Test
    void anonymousFactoryRejectsActionsThatRequireKnownIdentity() {
        assertThrows(
                IllegalArgumentException.class,
                () -> AuthenticationAuditEvent.recordAnonymous(
                        IdentityActorType.RETAIL_CUSTOMER,
                        AuthenticationAction.TOKEN_PAIR_ISSUED,
                        AuthenticationDecision.SUCCESS,
                        AuthenticationMethod.JWT,
                        "TOKENS_ISSUED",
                        "invalid-anonymous-correlation",
                        OCCURRED_AT
                )
        );
    }
}
