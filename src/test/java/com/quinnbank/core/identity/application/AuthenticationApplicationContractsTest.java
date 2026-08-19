package com.quinnbank.core.identity.application;

import com.quinnbank.core.identity.application.command.LoginIdentityCommand;
import com.quinnbank.core.identity.application.command.RefreshTokenCommand;
import com.quinnbank.core.identity.application.command.ProvisionCustomerIdentityCommand;
import com.quinnbank.core.identity.application.policy.AuthenticationPolicy;
import com.quinnbank.core.identity.application.policy.RegistrationPasswordPolicy;
import com.quinnbank.core.identity.application.result.IssuedTokenPair;
import com.quinnbank.core.identity.application.result.AuthenticatedSubject;
import com.quinnbank.core.identity.application.result.IdentitySubjectType;
import com.quinnbank.core.identity.application.result.ProvisionedIdentityStatus;
import com.quinnbank.core.identity.application.result.ProvisionedCustomerIdentity;
import com.quinnbank.core.identity.application.result.VerifiedRefreshToken;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthenticationApplicationContractsTest {
    private static final Instant ISSUED_AT = Instant.parse("2026-08-04T01:00:00Z");

    private final RegistrationPasswordPolicy passwordPolicy = new RegistrationPasswordPolicy();

    @Test
    void commandsRequirePresentFieldsAndRedactSensitiveValues() {
        ProvisionCustomerIdentityCommand provisioning = new ProvisionCustomerIdentityCommand(
                UUID.fromString("40000000-0000-0000-0000-000000000004"),
                "synthetic-user@example.invalid",
                "synthetic-correlation",
                "192.0.2.1"
        );
        LoginIdentityCommand login = new LoginIdentityCommand(
                "synthetic-user@example.invalid",
                "synthetic-password",
                "synthetic-correlation",
                "192.0.2.1"
        );
        RefreshTokenCommand refresh = new RefreshTokenCommand(
                "synthetic-refresh-token",
                "synthetic-correlation",
                "192.0.2.1"
        );

        assertAll(
                () -> assertFalse(provisioning.toString().contains(provisioning.loginIdentifier())),
                () -> assertFalse(login.toString().contains(login.loginIdentifier())),
                () -> assertFalse(login.toString().contains(login.rawPassword())),
                () -> assertFalse(refresh.toString().contains(refresh.refreshToken())),
                () -> assertThrows(
                        NullPointerException.class,
                        () -> new ProvisionCustomerIdentityCommand(
                                UUID.fromString("40000000-0000-0000-0000-000000000004"),
                                null,
                                "synthetic-correlation",
                                "192.0.2.1"
                        )
                ),
                () -> assertThrows(
                        NullPointerException.class,
                        () -> new RefreshTokenCommand(null, "synthetic-correlation", "192.0.2.1")
                )
        );
    }

    @Test
    void tokenResultsDoNotExposeTokensOrSessionIdentifiers() {
        String accessToken = "synthetic-access-token";
        String refreshToken = "synthetic-refresh-token";
        UUID sessionId = UUID.fromString("10000000-0000-0000-0000-000000000001");
        UUID tokenId = UUID.fromString("20000000-0000-0000-0000-000000000002");
        IssuedTokenPair pair = new IssuedTokenPair(
                UUID.fromString("30000000-0000-0000-0000-000000000003"),
                accessToken,
                ISSUED_AT.plusSeconds(300),
                refreshToken,
                ISSUED_AT.plusSeconds(3_600)
        );
        VerifiedRefreshToken verified = new VerifiedRefreshToken(
                pair.identityId(),
                IdentityActorType.RETAIL_CUSTOMER,
                sessionId,
                tokenId,
                ISSUED_AT,
                pair.refreshExpiresAt()
        );
        UUID customerId = UUID.fromString("40000000-0000-0000-0000-000000000004");
        AuthenticatedSubject subject = new AuthenticatedSubject(
                pair.identityId(),
                IdentitySubjectType.RETAIL_CUSTOMER,
                customerId
        );
        ProvisionedCustomerIdentity provisioned = new ProvisionedCustomerIdentity(
                pair.identityId(),
                customerId,
                IdentitySubjectType.RETAIL_CUSTOMER,
                ProvisionedIdentityStatus.DISABLED
        );

        assertAll(
                () -> assertFalse(pair.toString().contains(accessToken)),
                () -> assertFalse(pair.toString().contains(refreshToken)),
                () -> assertFalse(verified.toString().contains(sessionId.toString())),
                () -> assertFalse(verified.toString().contains(tokenId.toString())),
                () -> assertFalse(subject.toString().contains(pair.identityId().toString())),
                () -> assertFalse(subject.toString().contains(customerId.toString())),
                () -> assertFalse(provisioned.toString().contains(pair.identityId().toString())),
                () -> assertFalse(provisioned.toString().contains(customerId.toString()))
        );
    }

    @Test
    void registrationPasswordPolicyUsesCharacterAndUtf8ByteBoundariesWithoutTrimming() {
        assertAll(
                () -> assertDoesNotThrow(() -> passwordPolicy.validate(" abcdefghij ")),
                () -> assertDoesNotThrow(() -> passwordPolicy.validate("\uD83D\uDE00".repeat(18))),
                () -> assertThrows(
                        IllegalArgumentException.class,
                        () -> passwordPolicy.validate("abcdefghijk")
                ),
                () -> assertThrows(
                        IllegalArgumentException.class,
                        () -> passwordPolicy.validate("\uD83D\uDE00".repeat(19))
                ),
                () -> assertThrows(
                        IllegalArgumentException.class,
                        () -> passwordPolicy.validate("validlength\npassword")
                )
        );
    }

    @Test
    void authenticationPolicyRejectsInvalidLockAndRefreshDurations() {
        assertAll(
                () -> assertDoesNotThrow(
                        () -> new AuthenticationPolicy(5, Duration.ofMinutes(15), Duration.ofDays(7))
                ),
                () -> assertThrows(
                        IllegalArgumentException.class,
                        () -> new AuthenticationPolicy(0, Duration.ofMinutes(15), Duration.ofDays(7))
                ),
                () -> assertThrows(
                        IllegalArgumentException.class,
                        () -> new AuthenticationPolicy(5, Duration.ZERO, Duration.ofDays(7))
                ),
                () -> assertThrows(
                        IllegalArgumentException.class,
                        () -> new AuthenticationPolicy(5, Duration.ofMinutes(15), Duration.ZERO)
                )
        );
    }
}
