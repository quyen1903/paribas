package com.quinnbank.core.identity.domain;

import com.quinnbank.core.identity.domain.enums.AuthenticationAction;
import com.quinnbank.core.identity.domain.enums.AuthenticationDecision;
import com.quinnbank.core.identity.domain.enums.AuthenticationMethod;
import com.quinnbank.core.identity.domain.enums.IdentityAccountStatus;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdentityAccountTest {
    private static final UUID IDENTITY_ID = UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final UUID SUBJECT_ID = UUID.fromString("20000000-0000-0000-0000-000000000002");
    private static final Instant CREATED_AT = Instant.parse("2026-08-04T01:00:00Z");
    private static final Duration LOCK_DURATION = Duration.ofMinutes(15);
    private static final String ORIGINAL_PASSWORD = fakeEncodedPassword('A');
    private static final String REPLACEMENT_PASSWORD = fakeEncodedPassword('B');
    private static final AuthenticationActor OPERATOR = AuthenticationActor.of(
            IdentityActorType.BACK_OFFICE_OPERATOR,
            "synthetic-operator-001"
    );

    @Test
    void provisionNormalizesLoginDefaultsToDisabledAndRecordsAudit() {
        IdentityAccount account = provisionAccount();

        assertAll(
                () -> assertEquals(IDENTITY_ID, account.getId()),
                () -> assertEquals(SUBJECT_ID, account.getSubjectId()),
                () -> assertEquals(IdentityActorType.RETAIL_CUSTOMER, account.getActorType()),
                () -> assertEquals("customer@example.invalid", account.getLoginIdentifier()),
                () -> assertEquals(ORIGINAL_PASSWORD, account.getEncodedPasswordForAuthentication()),
                () -> assertEquals(IdentityAccountStatus.DISABLED, account.getStatus()),
                () -> assertEquals(0, account.getFailedAuthenticationAttempts()),
                () -> assertNull(account.getLockedUntil()),
                () -> assertNull(account.getLastAuthenticatedAt()),
                () -> assertEquals(CREATED_AT, account.getCredentialsChangedAt()),
                () -> assertEquals(CREATED_AT, account.getCreatedAt()),
                () -> assertEquals(CREATED_AT, account.getUpdatedAt()),
                () -> assertFalse(account.canAuthenticate(CREATED_AT))
        );

        AuthenticationAuditEvent event = singleReleasedEvent(account);
        assertAuditEvent(
                event,
                OPERATOR,
                AuthenticationAction.ACCOUNT_PROVISIONED,
                AuthenticationDecision.SUCCESS,
                null,
                "ACCOUNT_PROVISIONED",
                "provision-correlation",
                CREATED_AT
        );
        assertTrue(account.releaseAuditEvents().isEmpty());
    }

    @Test
    void passwordBasedProvisioningRejectsServiceActors() {
        List<IdentityActorType> nonPasswordActors = List.of(
                IdentityActorType.SERVICE_ACCOUNT,
                IdentityActorType.THIRD_PARTY_PARTNER,
                IdentityActorType.BATCH_JOB
        );

        for (IdentityActorType actorType : nonPasswordActors) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> IdentityAccount.provision(
                            UUID.randomUUID(),
                            UUID.randomUUID(),
                            actorType,
                            "service@example.invalid",
                            EncodedPassword.fromPasswordEncoder(ORIGINAL_PASSWORD),
                            OPERATOR,
                            "service-provision-correlation",
                            CREATED_AT
                    ),
                    () -> actorType + " must use a non-password authentication design"
            );
        }
    }

    @Test
    void customerProvisioningRejectsAnIdentityThatPointsToItselfAsTheBusinessSubject() {
        for (IdentityActorType actorType : List.of(
                IdentityActorType.RETAIL_CUSTOMER,
                IdentityActorType.BUSINESS_CUSTOMER
        )) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> IdentityAccount.provision(
                            IDENTITY_ID,
                            IDENTITY_ID,
                            actorType,
                            "customer@example.invalid",
                            EncodedPassword.fromPasswordEncoder(ORIGINAL_PASSWORD),
                            OPERATOR,
                            "invalid-subject-binding",
                            CREATED_AT
                    )
            );
        }
    }

    @Test
    void enabledAccountCanAuthenticateAndSuccessfulAuthenticationResetsFailureState() {
        IdentityAccount account = provisionAccount();
        account.releaseAuditEvents();

        Instant enabledAt = CREATED_AT.plusSeconds(30);
        account.enable(OPERATOR, "enable-correlation", enabledAt);

        assertAll(
                () -> assertEquals(IdentityAccountStatus.ACTIVE, account.getStatus()),
                () -> assertTrue(account.canAuthenticate(enabledAt)),
                () -> assertEquals(enabledAt, account.getUpdatedAt())
        );
        assertAuditEvent(
                singleReleasedEvent(account),
                OPERATOR,
                AuthenticationAction.ACCOUNT_ENABLED,
                AuthenticationDecision.SUCCESS,
                null,
                "ACCOUNT_ENABLED",
                "enable-correlation",
                enabledAt
        );

        Instant failedAt = enabledAt.plusSeconds(30);
        account.recordAuthenticationFailure(3, LOCK_DURATION, "failed-correlation", failedAt);
        account.releaseAuditEvents();

        Instant authenticatedAt = failedAt.plusSeconds(30);
        account.recordAuthenticationSuccess("success-correlation", authenticatedAt);

        assertAll(
                () -> assertTrue(account.canAuthenticate(authenticatedAt)),
                () -> assertEquals(0, account.getFailedAuthenticationAttempts()),
                () -> assertNull(account.getLockedUntil()),
                () -> assertEquals(authenticatedAt, account.getLastAuthenticatedAt()),
                () -> assertEquals(authenticatedAt, account.getUpdatedAt())
        );
        AuthenticationAuditEvent successEvent = singleReleasedEvent(account);
        assertAuditEvent(
                successEvent,
                AuthenticationActor.of(IdentityActorType.RETAIL_CUSTOMER, SUBJECT_ID.toString()),
                AuthenticationAction.AUTHENTICATION_SUCCEEDED,
                AuthenticationDecision.SUCCESS,
                AuthenticationMethod.PASSWORD,
                "CREDENTIALS_ACCEPTED",
                "success-correlation",
                authenticatedAt
        );
    }

    @Test
    void failedAttemptThresholdTemporarilyLocksAccountAndAuditsLockAction() {
        IdentityAccount account = activeAccount();
        Instant firstFailureAt = CREATED_AT.plus(Duration.ofMinutes(2));

        account.recordAuthenticationFailure(3, LOCK_DURATION, "failure-1", firstFailureAt);
        AuthenticationAuditEvent firstFailure = singleReleasedEvent(account);
        assertAuditEvent(
                firstFailure,
                AuthenticationActor.of(IdentityActorType.RETAIL_CUSTOMER, "ANONYMOUS"),
                AuthenticationAction.AUTHENTICATION_FAILED,
                AuthenticationDecision.FAILURE,
                AuthenticationMethod.PASSWORD,
                "INVALID_CREDENTIALS",
                "failure-1",
                firstFailureAt
        );

        account.recordAuthenticationFailure(3, LOCK_DURATION, "failure-2", firstFailureAt.plusSeconds(1));
        account.releaseAuditEvents();
        Instant lockedAt = firstFailureAt.plusSeconds(2);
        account.recordAuthenticationFailure(3, LOCK_DURATION, "failure-3", lockedAt);

        assertAll(
                () -> assertEquals(3, account.getFailedAuthenticationAttempts()),
                () -> assertEquals(lockedAt.plus(LOCK_DURATION), account.getLockedUntil()),
                () -> assertFalse(account.canAuthenticate(lockedAt)),
                () -> assertEquals(lockedAt, account.getUpdatedAt())
        );
        assertAuditEvent(
                singleReleasedEvent(account),
                AuthenticationActor.of(IdentityActorType.RETAIL_CUSTOMER, "ANONYMOUS"),
                AuthenticationAction.ACCOUNT_TEMPORARILY_LOCKED,
                AuthenticationDecision.FAILURE,
                AuthenticationMethod.PASSWORD,
                "FAILURE_THRESHOLD_REACHED",
                "failure-3",
                lockedAt
        );

        AccountState lockedState = AccountState.capture(account);
        assertThrows(
                IllegalStateException.class,
                () -> account.recordAuthenticationFailure(
                        3,
                        LOCK_DURATION,
                        "failure-while-locked",
                        lockedAt.plusSeconds(1)
                )
        );
        assertStateEquals(lockedState, account);
        assertTrue(account.releaseAuditEvents().isEmpty());
    }

    @Test
    void expiredLockStartsANewFailureWindow() {
        IdentityAccount account = activeAccount();
        Instant firstFailureAt = CREATED_AT.plus(Duration.ofMinutes(2));
        account.recordAuthenticationFailure(2, LOCK_DURATION, "failure-1", firstFailureAt);
        account.releaseAuditEvents();
        Instant lockedAt = firstFailureAt.plusSeconds(1);
        account.recordAuthenticationFailure(2, LOCK_DURATION, "failure-2", lockedAt);
        account.releaseAuditEvents();
        Instant lockExpiry = lockedAt.plus(LOCK_DURATION);

        assertTrue(account.canAuthenticate(lockExpiry));
        account.recordAuthenticationFailure(2, LOCK_DURATION, "failure-after-expiry", lockExpiry);

        assertAll(
                () -> assertEquals(1, account.getFailedAuthenticationAttempts()),
                () -> assertNull(account.getLockedUntil()),
                () -> assertTrue(account.canAuthenticate(lockExpiry)),
                () -> assertEquals(lockExpiry, account.getUpdatedAt())
        );
        assertAuditEvent(
                singleReleasedEvent(account),
                AuthenticationActor.of(IdentityActorType.RETAIL_CUSTOMER, "ANONYMOUS"),
                AuthenticationAction.AUTHENTICATION_FAILED,
                AuthenticationDecision.FAILURE,
                AuthenticationMethod.PASSWORD,
                "INVALID_CREDENTIALS",
                "failure-after-expiry",
                lockExpiry
        );
    }

    @Test
    void disabledAndClosedAccountsCannotAuthenticate() {
        IdentityAccount disabled = provisionAccount();
        disabled.releaseAuditEvents();
        AccountState disabledState = AccountState.capture(disabled);

        assertAll(
                () -> assertFalse(disabled.canAuthenticate(CREATED_AT.plusSeconds(1))),
                () -> assertThrows(
                        IllegalStateException.class,
                        () -> disabled.recordAuthenticationSuccess(
                                "disabled-success-correlation",
                                CREATED_AT.plusSeconds(1)
                        )
                ),
                () -> assertThrows(
                        IllegalStateException.class,
                        () -> disabled.recordAuthenticationFailure(
                                3,
                                LOCK_DURATION,
                                "disabled-failure-correlation",
                                CREATED_AT.plusSeconds(1)
                        )
                )
        );
        assertStateEquals(disabledState, disabled);
        assertTrue(disabled.releaseAuditEvents().isEmpty());

        IdentityAccount closed = activeAccount();
        Instant closedAt = CREATED_AT.plus(Duration.ofMinutes(2));
        closed.close(OPERATOR, "CUSTOMER_REQUEST", "close-correlation", closedAt);
        closed.releaseAuditEvents();
        AccountState closedState = AccountState.capture(closed);

        assertAll(
                () -> assertFalse(closed.canAuthenticate(closedAt.plusSeconds(1))),
                () -> assertThrows(
                        IllegalStateException.class,
                        () -> closed.recordAuthenticationSuccess(
                                "closed-success-correlation",
                                closedAt.plusSeconds(1)
                        )
                ),
                () -> assertThrows(
                        IllegalStateException.class,
                        () -> closed.recordAuthenticationFailure(
                                3,
                                LOCK_DURATION,
                                "closed-failure-correlation",
                                closedAt.plusSeconds(1)
                        )
                )
        );
        assertStateEquals(closedState, closed);
        assertTrue(closed.releaseAuditEvents().isEmpty());
    }

    @Test
    void changingPasswordResetsLockAndDoesNotExposeSecrets() {
        IdentityAccount account = activeAccount();
        Instant firstFailureAt = CREATED_AT.plus(Duration.ofMinutes(2));
        account.recordAuthenticationFailure(2, LOCK_DURATION, "failure-1", firstFailureAt);
        account.releaseAuditEvents();
        account.recordAuthenticationFailure(2, LOCK_DURATION, "failure-2", firstFailureAt.plusSeconds(1));
        account.releaseAuditEvents();
        Instant passwordChangedAt = firstFailureAt.plusSeconds(2);

        account.changePassword(
                EncodedPassword.fromPasswordEncoder(REPLACEMENT_PASSWORD),
                OPERATOR,
                "password-change-correlation",
                passwordChangedAt
        );

        assertAll(
                () -> assertEquals(REPLACEMENT_PASSWORD, account.getEncodedPasswordForAuthentication()),
                () -> assertEquals(0, account.getFailedAuthenticationAttempts()),
                () -> assertNull(account.getLockedUntil()),
                () -> assertEquals(passwordChangedAt, account.getCredentialsChangedAt()),
                () -> assertEquals(passwordChangedAt, account.getUpdatedAt()),
                () -> assertFalse(account.toString().contains(ORIGINAL_PASSWORD)),
                () -> assertFalse(account.toString().contains(REPLACEMENT_PASSWORD)),
                () -> assertFalse(OPERATOR.toString().contains(OPERATOR.id()))
        );

        AuthenticationAuditEvent event = singleReleasedEvent(account);
        assertAuditEvent(
                event,
                OPERATOR,
                AuthenticationAction.PASSWORD_CHANGED,
                AuthenticationDecision.SUCCESS,
                AuthenticationMethod.PASSWORD,
                "PASSWORD_CHANGED",
                "password-change-correlation",
                passwordChangedAt
        );
        assertAll(
                () -> assertFalse(event.toString().contains(ORIGINAL_PASSWORD)),
                () -> assertFalse(event.toString().contains(REPLACEMENT_PASSWORD)),
                () -> assertFalse(event.toString().contains(OPERATOR.id())),
                () -> assertFalse(event.toString().contains(event.getCorrelationId()))
        );
    }

    @Test
    void backwardsTransitionTimesAreRejectedWithoutMutation() {
        List<NamedTransition> activeTransitions = List.of(
                new NamedTransition(
                        "authentication failure",
                        account -> account.recordAuthenticationFailure(
                                3,
                                LOCK_DURATION,
                                "backwards-failure-correlation",
                                CREATED_AT
                        )
                ),
                new NamedTransition(
                        "authentication success",
                        account -> account.recordAuthenticationSuccess(
                                "backwards-success-correlation",
                                CREATED_AT
                        )
                ),
                new NamedTransition(
                        "password change",
                        account -> account.changePassword(
                                EncodedPassword.fromPasswordEncoder(REPLACEMENT_PASSWORD),
                                OPERATOR,
                                "backwards-password-correlation",
                                CREATED_AT
                        )
                ),
                new NamedTransition(
                        "disable",
                        account -> account.disable(
                                OPERATOR,
                                "SECURITY_REVIEW",
                                "backwards-disable-correlation",
                                CREATED_AT
                        )
                ),
                new NamedTransition(
                        "close",
                        account -> account.close(
                                OPERATOR,
                                "CUSTOMER_REQUEST",
                                "backwards-close-correlation",
                                CREATED_AT
                        )
                )
        );

        for (NamedTransition transition : activeTransitions) {
            IdentityAccount account = activeAccount();
            AccountState before = AccountState.capture(account);

            assertThrows(
                    IllegalArgumentException.class,
                    () -> transition.transition().accept(account),
                    transition.name()
            );
            assertStateEquals(before, account);
            assertTrue(account.releaseAuditEvents().isEmpty(), transition.name());
        }

        IdentityAccount disabled = provisionAccount();
        disabled.releaseAuditEvents();
        AccountState beforeEnable = AccountState.capture(disabled);
        assertThrows(
                IllegalArgumentException.class,
                () -> disabled.enable(
                        OPERATOR,
                        "backwards-enable-correlation",
                        CREATED_AT.minusSeconds(1)
                )
        );
        assertStateEquals(beforeEnable, disabled);
        assertTrue(disabled.releaseAuditEvents().isEmpty());
    }

    @Test
    void invalidCorrelationIdDoesNotPartiallyMutate() {
        List<NamedTransition> transitions = List.of(
                new NamedTransition(
                        "authentication failure",
                        account -> account.recordAuthenticationFailure(
                                3,
                                LOCK_DURATION,
                                "invalid\ncorrelation",
                                CREATED_AT.plus(Duration.ofMinutes(2))
                        )
                ),
                new NamedTransition(
                        "authentication success",
                        account -> account.recordAuthenticationSuccess(
                                "invalid\ncorrelation",
                                CREATED_AT.plus(Duration.ofMinutes(2))
                        )
                ),
                new NamedTransition(
                        "password change",
                        account -> account.changePassword(
                                EncodedPassword.fromPasswordEncoder(REPLACEMENT_PASSWORD),
                                OPERATOR,
                                "invalid\ncorrelation",
                                CREATED_AT.plus(Duration.ofMinutes(2))
                        )
                ),
                new NamedTransition(
                        "disable",
                        account -> account.disable(
                                OPERATOR,
                                "SECURITY_REVIEW",
                                "invalid\ncorrelation",
                                CREATED_AT.plus(Duration.ofMinutes(2))
                        )
                ),
                new NamedTransition(
                        "close",
                        account -> account.close(
                                OPERATOR,
                                "CUSTOMER_REQUEST",
                                "invalid\ncorrelation",
                                CREATED_AT.plus(Duration.ofMinutes(2))
                        )
                )
        );

        for (NamedTransition transition : transitions) {
            IdentityAccount account = activeAccountWithOneFailure();
            AccountState before = AccountState.capture(account);

            assertThrows(
                    IllegalArgumentException.class,
                    () -> transition.transition().accept(account),
                    transition.name()
            );
            assertStateEquals(before, account);
            assertTrue(account.releaseAuditEvents().isEmpty(), transition.name());
        }

        IdentityAccount disabled = provisionAccount();
        disabled.releaseAuditEvents();
        AccountState beforeEnable = AccountState.capture(disabled);
        assertThrows(
                IllegalArgumentException.class,
                () -> disabled.enable(
                        OPERATOR,
                        "invalid\ncorrelation",
                        CREATED_AT.plus(Duration.ofMinutes(2))
                )
        );
        assertStateEquals(beforeEnable, disabled);
        assertTrue(disabled.releaseAuditEvents().isEmpty());
    }

    @Test
    void invalidReasonCodeDoesNotPartiallyMutate() {
        IdentityAccount accountToDisable = activeAccountWithOneFailure();
        AccountState beforeDisable = AccountState.capture(accountToDisable);
        assertThrows(
                IllegalArgumentException.class,
                () -> accountToDisable.disable(
                        OPERATOR,
                        "lowercase-reason",
                        "disable-correlation",
                        CREATED_AT.plus(Duration.ofMinutes(3))
                )
        );
        assertStateEquals(beforeDisable, accountToDisable);
        assertTrue(accountToDisable.releaseAuditEvents().isEmpty());

        IdentityAccount accountToClose = activeAccountWithOneFailure();
        AccountState beforeClose = AccountState.capture(accountToClose);
        assertThrows(
                IllegalArgumentException.class,
                () -> accountToClose.close(
                        OPERATOR,
                        "lowercase-reason",
                        "close-correlation",
                        CREATED_AT.plus(Duration.ofMinutes(3))
                )
        );
        assertStateEquals(beforeClose, accountToClose);
        assertTrue(accountToClose.releaseAuditEvents().isEmpty());
    }

    @Test
    void lifecycleAuditEventsUseExpectedActionsAndReleaseAsImmutableBatch() {
        IdentityAccount account = activeAccount();
        Instant disabledAt = CREATED_AT.plus(Duration.ofMinutes(2));
        account.disable(OPERATOR, "SECURITY_REVIEW", "disable-correlation", disabledAt);
        Instant enabledAt = disabledAt.plus(Duration.ofMinutes(1));
        account.enable(OPERATOR, "reenable-correlation", enabledAt);
        Instant closedAt = enabledAt.plus(Duration.ofMinutes(1));
        account.close(OPERATOR, "CUSTOMER_REQUEST", "close-correlation", closedAt);

        List<AuthenticationAuditEvent> events = account.releaseAuditEvents();

        assertEquals(
                List.of(
                        AuthenticationAction.ACCOUNT_DISABLED,
                        AuthenticationAction.ACCOUNT_ENABLED,
                        AuthenticationAction.ACCOUNT_CLOSED
                ),
                events.stream().map(AuthenticationAuditEvent::getAction).toList()
        );
        assertEquals(
                List.of("SECURITY_REVIEW", "ACCOUNT_ENABLED", "CUSTOMER_REQUEST"),
                events.stream().map(AuthenticationAuditEvent::getReasonCode).toList()
        );
        assertTrue(events.stream().allMatch(event -> event.getDecision() == AuthenticationDecision.SUCCESS));
        assertTrue(events.stream().allMatch(event -> event.getAuthenticationMethod() == null));
        assertThrows(UnsupportedOperationException.class, events::clear);
        assertEquals(3, events.size());
        assertTrue(account.releaseAuditEvents().isEmpty());
    }

    private static IdentityAccount provisionAccount() {
        return IdentityAccount.provision(
                IDENTITY_ID,
                SUBJECT_ID,
                IdentityActorType.RETAIL_CUSTOMER,
                "  Customer@Example.Invalid  ",
                EncodedPassword.fromPasswordEncoder(ORIGINAL_PASSWORD),
                OPERATOR,
                "provision-correlation",
                CREATED_AT
        );
    }

    private static IdentityAccount activeAccount() {
        IdentityAccount account = provisionAccount();
        account.releaseAuditEvents();
        account.enable(OPERATOR, "enable-correlation", CREATED_AT.plus(Duration.ofMinutes(1)));
        account.releaseAuditEvents();
        return account;
    }

    private static IdentityAccount activeAccountWithOneFailure() {
        IdentityAccount account = activeAccount();
        account.recordAuthenticationFailure(
                3,
                LOCK_DURATION,
                "initial-failure-correlation",
                CREATED_AT.plusSeconds(90)
        );
        account.releaseAuditEvents();
        return account;
    }

    private static AuthenticationAuditEvent singleReleasedEvent(IdentityAccount account) {
        List<AuthenticationAuditEvent> events = account.releaseAuditEvents();
        assertEquals(1, events.size());
        return events.getFirst();
    }

    private static void assertAuditEvent(
            AuthenticationAuditEvent event,
            AuthenticationActor expectedActor,
            AuthenticationAction expectedAction,
            AuthenticationDecision expectedDecision,
            AuthenticationMethod expectedMethod,
            String expectedReasonCode,
            String expectedCorrelationId,
            Instant expectedOccurredAt
    ) {
        assertAll(
                () -> assertNotNull(event.getId()),
                () -> assertEquals(IDENTITY_ID, event.getTargetIdentityId()),
                () -> assertEquals(expectedActor.type(), event.getActorType()),
                () -> assertEquals(expectedActor.id(), event.getActorId()),
                () -> assertEquals(expectedAction, event.getAction()),
                () -> assertEquals(expectedDecision, event.getDecision()),
                () -> assertEquals(expectedMethod, event.getAuthenticationMethod()),
                () -> assertEquals(expectedReasonCode, event.getReasonCode()),
                () -> assertEquals(expectedCorrelationId, event.getCorrelationId()),
                () -> assertEquals(expectedOccurredAt, event.getOccurredAt())
        );
    }

    private static void assertStateEquals(AccountState expected, IdentityAccount actual) {
        assertEquals(expected, AccountState.capture(actual));
    }

    private static String fakeEncodedPassword(char content) {
        return "$2b$12$" + String.valueOf(content).repeat(53);
    }

    private record NamedTransition(String name, Consumer<IdentityAccount> transition) {
    }

    private record AccountState(
            IdentityAccountStatus status,
            int failedAuthenticationAttempts,
            Instant lockedUntil,
            Instant credentialsChangedAt,
            Instant lastAuthenticatedAt,
            Instant updatedAt,
            String encodedPassword
    ) {
        private static AccountState capture(IdentityAccount account) {
            return new AccountState(
                    account.getStatus(),
                    account.getFailedAuthenticationAttempts(),
                    account.getLockedUntil(),
                    account.getCredentialsChangedAt(),
                    account.getLastAuthenticatedAt(),
                    account.getUpdatedAt(),
                    account.getEncodedPasswordForAuthentication()
            );
        }
    }
}
