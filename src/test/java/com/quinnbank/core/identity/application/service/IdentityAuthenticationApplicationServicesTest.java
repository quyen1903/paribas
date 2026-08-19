package com.quinnbank.core.identity.application.service;

import com.quinnbank.core.identity.application.command.LoginIdentityCommand;
import com.quinnbank.core.identity.application.command.RefreshTokenCommand;
import com.quinnbank.core.identity.application.command.ProvisionCustomerIdentityCommand;
import com.quinnbank.core.identity.application.exception.InvalidCredentialsException;
import com.quinnbank.core.identity.application.exception.IdentityProvisioningConflictException;
import com.quinnbank.core.identity.application.exception.InvalidRefreshTokenException;
import com.quinnbank.core.identity.application.policy.AuthenticationPolicy;
import com.quinnbank.core.identity.application.policy.AuthenticationTimestampPolicy;
import com.quinnbank.core.identity.application.policy.RegistrationPasswordPolicy;
import com.quinnbank.core.identity.application.port.AuthenticationAuditRepository;
import com.quinnbank.core.identity.application.port.AuthenticationSessionRepository;
import com.quinnbank.core.identity.application.port.AuthenticationThrottle;
import com.quinnbank.core.identity.application.port.IdentityAccountRepository;
import com.quinnbank.core.identity.application.port.PasswordService;
import com.quinnbank.core.identity.application.port.TokenPairService;
import com.quinnbank.core.identity.application.result.IssuedTokenPair;
import com.quinnbank.core.identity.application.result.IdentitySubjectType;
import com.quinnbank.core.identity.application.result.ProvisionedIdentityStatus;
import com.quinnbank.core.identity.application.result.ProvisionedCustomerIdentity;
import com.quinnbank.core.identity.application.result.VerifiedRefreshToken;
import com.quinnbank.core.identity.domain.AuthenticationActor;
import com.quinnbank.core.identity.domain.AuthenticationAuditEvent;
import com.quinnbank.core.identity.domain.AuthenticationSession;
import com.quinnbank.core.identity.domain.EncodedPassword;
import com.quinnbank.core.identity.domain.IdentityAccount;
import com.quinnbank.core.identity.domain.enums.AuthenticationAction;
import com.quinnbank.core.identity.domain.enums.AuthenticationSessionStatus;
import com.quinnbank.core.identity.domain.enums.IdentityAccountStatus;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdentityAuthenticationApplicationServicesTest {
    private static final Instant NOW = Instant.parse("2026-08-04T10:15:30Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final Duration REFRESH_TTL = Duration.ofDays(7);
    private static final AuthenticationPolicy AUTHENTICATION_POLICY = new AuthenticationPolicy(
            5,
            Duration.ofMinutes(15),
            REFRESH_TTL
    );
    private static final String LOGIN_IDENTIFIER = "retail-user@example.invalid";
    private static final String RAW_PASSWORD = "synthetic-correct-password";
    private static final String WRONG_PASSWORD = "synthetic-wrong-password";
    private static final String ENCODED_PASSWORD = "$2b$12$" + "a".repeat(53);
    private static final String UNUSABLE_ENCODED_PASSWORD = "$2b$12$" + "u".repeat(53);
    private static final String CORRELATION_ID = "application-test-correlation";
    private static final String SOURCE_ADDRESS = "192.0.2.42";
    private static final UUID CUSTOMER_ID = UUID.fromString("40000000-0000-0000-0000-000000000004");
    @Test
    void provisioningBindsTheCustomerSubjectAndLeavesActivationAndTokensForASeparateFlow() {
        Fixture fixture = new Fixture();
        ProvisionCustomerIdentityService service = fixture.provisionService();

        ProvisionedCustomerIdentity result = service.provision(new ProvisionCustomerIdentityCommand(
                CUSTOMER_ID,
                "  Retail-User@Example.Invalid  ",
                CORRELATION_ID,
                SOURCE_ADDRESS
        ));

        IdentityAccount persistedIdentity = fixture.identities.findById(result.identityId()).orElseThrow();

        assertAll(
                () -> assertEquals(IdentityActorType.RETAIL_CUSTOMER, persistedIdentity.getActorType()),
                () -> assertEquals(
                        IdentitySubjectType.RETAIL_CUSTOMER,
                        result.actorType()
                ),
                () -> assertEquals(
                        ProvisionedIdentityStatus.DISABLED,
                        result.status()
                ),
                () -> assertEquals(CUSTOMER_ID, persistedIdentity.getSubjectId()),
                () -> assertNotEquals(persistedIdentity.getId(), persistedIdentity.getSubjectId()),
                () -> assertEquals(LOGIN_IDENTIFIER, persistedIdentity.getLoginIdentifier()),
                () -> assertEquals(IdentityAccountStatus.DISABLED, persistedIdentity.getStatus()),
                () -> assertEquals(
                        UNUSABLE_ENCODED_PASSWORD,
                        persistedIdentity.getEncodedPasswordForAuthentication()
                ),
                () -> assertNotEquals(RAW_PASSWORD, persistedIdentity.getEncodedPasswordForAuthentication()),
                () -> assertFalse(persistedIdentity.toString().contains(RAW_PASSWORD)),
                () -> assertTrue(fixture.passwords.encodedInputs.isEmpty()),
                () -> assertEquals(1, fixture.passwords.unusableCredentialCount),
                () -> assertTrue(fixture.sessions.sessions.isEmpty()),
                () -> assertEquals(0, fixture.tokenPairs.issueCount),
                () -> assertEquals(SOURCE_ADDRESS, fixture.throttle.lastRegistrationSource),
                () -> assertEquals(
                        List.of(AuthenticationAction.ACCOUNT_PROVISIONED),
                        fixture.audits.actions()
                ),
                () -> assertEquals(IdentityActorType.SERVICE_ACCOUNT,
                        fixture.audits.events.getFirst().getActorType()),
                () -> assertEquals("cif-onboarding", fixture.audits.events.getFirst().getActorId())
        );
    }

    @Test
    void exactProvisioningReplayReturnsTheSameDisabledIdentityWithoutDuplicateAudit() {
        Fixture fixture = new Fixture();
        ProvisionCustomerIdentityService service = fixture.provisionService();
        ProvisionCustomerIdentityCommand command = new ProvisionCustomerIdentityCommand(
                CUSTOMER_ID,
                LOGIN_IDENTIFIER,
                CORRELATION_ID,
                SOURCE_ADDRESS
        );

        ProvisionedCustomerIdentity first = service.provision(command);
        ProvisionedCustomerIdentity replay = service.provision(command);

        assertAll(
                () -> assertEquals(first, replay),
                () -> assertEquals(1, fixture.identities.identities.size()),
                () -> assertEquals(List.of(AuthenticationAction.ACCOUNT_PROVISIONED), fixture.audits.actions()),
                () -> assertEquals(1, fixture.passwords.unusableCredentialCount),
                () -> assertEquals(0, fixture.passwords.matchCount)
        );
    }

    @Test
    void provisioningRejectsAReplayForAnIdentityThatHasAlreadyBeenEnabled() {
        Fixture fixture = new Fixture();
        ProvisionCustomerIdentityService service = fixture.provisionService();
        ProvisionCustomerIdentityCommand command = new ProvisionCustomerIdentityCommand(
                CUSTOMER_ID,
                LOGIN_IDENTIFIER,
                CORRELATION_ID,
                SOURCE_ADDRESS
        );
        ProvisionedCustomerIdentity provisioned = service.provision(command);
        IdentityAccount existing = fixture.identities.findById(provisioned.identityId()).orElseThrow();
        existing.enable(
                AuthenticationActor.of(IdentityActorType.SERVICE_ACCOUNT, "synthetic-activation"),
                CORRELATION_ID,
                NOW.plusSeconds(1)
        );

        assertThrows(IdentityProvisioningConflictException.class, () -> service.provision(command));
    }

    @Test
    void provisioningRejectsAReplayForAClosedIdentity() {
        Fixture fixture = new Fixture();
        ProvisionCustomerIdentityService service = fixture.provisionService();
        ProvisionCustomerIdentityCommand command = new ProvisionCustomerIdentityCommand(
                CUSTOMER_ID,
                LOGIN_IDENTIFIER,
                CORRELATION_ID,
                SOURCE_ADDRESS
        );
        ProvisionedCustomerIdentity provisioned = service.provision(command);
        IdentityAccount existing = fixture.identities.findById(provisioned.identityId()).orElseThrow();
        existing.close(
                AuthenticationActor.of(IdentityActorType.SERVICE_ACCOUNT, "synthetic-closure"),
                "CUSTOMER_IDENTITY_CLOSED",
                CORRELATION_ID,
                NOW.plusSeconds(1)
        );

        assertThrows(IdentityProvisioningConflictException.class, () -> service.provision(command));
    }

    @Test
    void newlyProvisionedIdentityCannotLoginBeforeASeparateActivationFlow() {
        Fixture fixture = new Fixture();
        ProvisionedCustomerIdentity provisioned = fixture.provisionService().provision(
                new ProvisionCustomerIdentityCommand(
                        CUSTOMER_ID,
                        LOGIN_IDENTIFIER,
                        CORRELATION_ID,
                        SOURCE_ADDRESS
                )
        );

        assertAll(
                () -> assertThrows(
                        InvalidCredentialsException.class,
                        () -> fixture.loginService().login(new LoginIdentityCommand(
                                LOGIN_IDENTIFIER,
                                RAW_PASSWORD,
                                CORRELATION_ID,
                                SOURCE_ADDRESS
                        ))
                ),
                () -> assertEquals(
                        IdentityAccountStatus.DISABLED,
                        fixture.identities.findById(provisioned.identityId()).orElseThrow().getStatus()
                ),
                () -> assertTrue(fixture.sessions.sessions.isEmpty()),
                () -> assertEquals(0, fixture.tokenPairs.issueCount)
        );
    }

    @Test
    void provisioningRejectsAConflictingReplayWithoutChangingIdentity() {
        Fixture fixture = new Fixture();
        ProvisionCustomerIdentityService service = fixture.provisionService();
        ProvisionCustomerIdentityCommand command = new ProvisionCustomerIdentityCommand(
                CUSTOMER_ID,
                LOGIN_IDENTIFIER,
                CORRELATION_ID,
                SOURCE_ADDRESS
        );
        ProvisionedCustomerIdentity provisioned = service.provision(command);

        assertAll(
                () -> assertThrows(
                        IdentityProvisioningConflictException.class,
                        () -> service.provision(new ProvisionCustomerIdentityCommand(
                                CUSTOMER_ID,
                                "changed-login@example.invalid",
                                CORRELATION_ID,
                                SOURCE_ADDRESS
                        ))
                ),
                () -> assertEquals(1, fixture.identities.identities.size()),
                () -> assertEquals(IdentityAccountStatus.DISABLED,
                        fixture.identities.findById(provisioned.identityId()).orElseThrow().getStatus()),
                () -> assertEquals(List.of(AuthenticationAction.ACCOUNT_PROVISIONED), fixture.audits.actions())
        );
    }

    @Test
    void successfulLoginUpdatesTheIdentityOpensASessionAndAuditsTokenIssuance() {
        Fixture fixture = new Fixture();
        IdentityAccount identity = fixture.addActiveIdentity(LOGIN_IDENTIFIER);
        LoginIdentityService service = fixture.loginService();

        IssuedTokenPair result = service.login(new LoginIdentityCommand(
                "  RETAIL-USER@EXAMPLE.INVALID ",
                RAW_PASSWORD,
                CORRELATION_ID,
                SOURCE_ADDRESS
        ));

        AuthenticationSession session = fixture.sessions.onlySession();
        assertAll(
                () -> assertEquals(identity.getId(), result.identityId()),
                () -> assertEquals(NOW, identity.getLastAuthenticatedAt()),
                () -> assertEquals(0, identity.getFailedAuthenticationAttempts()),
                () -> assertEquals(identity.getId(), session.getIdentityId()),
                () -> assertEquals(AuthenticationSessionStatus.ACTIVE, session.getStatus()),
                () -> assertEquals(LOGIN_IDENTIFIER, fixture.throttle.lastLoginIdentifier),
                () -> assertEquals(0, fixture.passwords.dummyMatchCount),
                () -> assertEquals(1, fixture.passwords.matchCount),
                () -> assertEquals(
                        List.of(
                                AuthenticationAction.AUTHENTICATION_SUCCEEDED,
                                AuthenticationAction.TOKEN_PAIR_ISSUED
                        ),
                        fixture.audits.actions()
                )
        );
    }

    @Test
    void wrongPasswordAndUnknownIdentityExposeTheSameFailureWhileKeepingAuditsScoped() {
        Fixture knownFixture = new Fixture();
        IdentityAccount knownIdentity = knownFixture.addActiveIdentity(LOGIN_IDENTIFIER);
        InvalidCredentialsException knownFailure = assertThrows(
                InvalidCredentialsException.class,
                () -> knownFixture.loginService().login(new LoginIdentityCommand(
                        LOGIN_IDENTIFIER,
                        WRONG_PASSWORD,
                        CORRELATION_ID,
                        SOURCE_ADDRESS
                ))
        );

        Fixture unknownFixture = new Fixture();
        String unknownIdentifier = "unknown-user@example.invalid";
        InvalidCredentialsException unknownFailure = assertThrows(
                InvalidCredentialsException.class,
                () -> unknownFixture.loginService().login(new LoginIdentityCommand(
                        unknownIdentifier,
                        WRONG_PASSWORD,
                        CORRELATION_ID,
                        SOURCE_ADDRESS
                ))
        );

        AuthenticationAuditEvent knownAudit = knownFixture.audits.events.getFirst();
        AuthenticationAuditEvent unknownAudit = unknownFixture.audits.events.getFirst();
        assertAll(
                () -> assertEquals(knownFailure.getClass(), unknownFailure.getClass()),
                () -> assertEquals(knownFailure.getMessage(), unknownFailure.getMessage()),
                () -> assertEquals(AuthenticationAction.AUTHENTICATION_FAILED, knownAudit.getAction()),
                () -> assertEquals(knownIdentity.getId(), knownAudit.getTargetIdentityId()),
                () -> assertEquals("ANONYMOUS", knownAudit.getActorId()),
                () -> assertEquals(1, knownIdentity.getFailedAuthenticationAttempts()),
                () -> assertEquals(1, knownFixture.passwords.matchCount),
                () -> assertEquals(0, knownFixture.passwords.dummyMatchCount),
                () -> assertEquals(AuthenticationAction.AUTHENTICATION_FAILED, unknownAudit.getAction()),
                () -> assertEquals(null, unknownAudit.getTargetIdentityId()),
                () -> assertEquals("ANONYMOUS", unknownAudit.getActorId()),
                () -> assertFalse(unknownAudit.toString().contains(unknownIdentifier)),
                () -> assertEquals(0, unknownFixture.passwords.matchCount),
                () -> assertEquals(1, unknownFixture.passwords.dummyMatchCount),
                () -> assertTrue(unknownFixture.sessions.sessions.isEmpty())
        );
    }

    @Test
    void refreshRotatesOnceAndReplayOfTheConsumedTokenRevokesTheSession() {
        Fixture fixture = new Fixture();
        IdentityAccount identity = fixture.addActiveIdentity(LOGIN_IDENTIFIER);
        UUID originalRefreshTokenId = UUID.fromString("10000000-0000-0000-0000-000000000001");
        UUID sessionId = UUID.fromString("20000000-0000-0000-0000-000000000002");
        AuthenticationSession session = AuthenticationSession.open(
                sessionId,
                identity.getId(),
                originalRefreshTokenId,
                NOW.plus(REFRESH_TTL),
                NOW.minusSeconds(1)
        );
        fixture.sessions.save(session);
        fixture.tokenPairs.verifiedRefreshToken = new VerifiedRefreshToken(
                identity.getId(),
                identity.getActorType(),
                sessionId,
                originalRefreshTokenId,
                NOW.minusSeconds(1),
                session.getExpiresAt()
        );
        RefreshTokenService service = fixture.refreshService();
        RefreshTokenCommand command = new RefreshTokenCommand(
                "synthetic-consumed-refresh-token",
                CORRELATION_ID,
                SOURCE_ADDRESS
        );

        IssuedTokenPair rotatedPair = service.refresh(command);
        UUID replacementRefreshTokenId = session.getCurrentRefreshTokenId();
        InvalidRefreshTokenException replayFailure = assertThrows(
                InvalidRefreshTokenException.class,
                () -> service.refresh(command)
        );

        assertAll(
                () -> assertNotNull(rotatedPair),
                () -> assertNotEquals(originalRefreshTokenId, replacementRefreshTokenId),
                () -> assertEquals(AuthenticationSessionStatus.REVOKED, session.getStatus()),
                () -> assertEquals("REFRESH_TOKEN_REPLAY_DETECTED", session.getRevocationReasonCode()),
                () -> assertEquals(1, fixture.tokenPairs.issueCount),
                () -> assertEquals(2, fixture.tokenPairs.verifiedInputs.size()),
                () -> assertEquals(
                        List.of(
                                AuthenticationAction.TOKEN_REFRESHED,
                                AuthenticationAction.REFRESH_TOKEN_REPLAY_DETECTED,
                                AuthenticationAction.SESSION_REVOKED
                        ),
                        fixture.audits.actions()
                ),
                () -> assertEquals("ANONYMOUS", fixture.audits.events.get(1).getActorId()),
                () -> assertEquals("ANONYMOUS", fixture.audits.events.get(2).getActorId()),
                () -> assertFalse(session.toString().contains(command.refreshToken())),
                () -> assertFalse(replayFailure.getMessage().contains(command.refreshToken()))
        );
    }

    @Test
    void refreshMatchesJwtExpiryAtCanonicalSecondPrecision() {
        Instant preciseNow = Instant.parse("2026-08-04T10:15:30.987654321Z");
        Instant canonicalNow = AuthenticationTimestampPolicy.jwtCompatible(preciseNow);
        Fixture fixture = new Fixture();
        IdentityAccount identity = fixture.addActiveIdentity(LOGIN_IDENTIFIER);
        UUID tokenId = UUID.randomUUID();
        AuthenticationSession session = AuthenticationSession.open(
                UUID.randomUUID(),
                identity.getId(),
                tokenId,
                preciseNow.plus(REFRESH_TTL),
                canonicalNow.minusSeconds(1)
        );
        fixture.sessions.save(session);
        fixture.tokenPairs.verifiedRefreshToken = new VerifiedRefreshToken(
                identity.getId(),
                identity.getActorType(),
                session.getId(),
                tokenId,
                canonicalNow.minusSeconds(1),
                AuthenticationTimestampPolicy.jwtCompatible(session.getExpiresAt())
        );
        RefreshTokenService service = new RefreshTokenService(
                fixture.identities,
                fixture.sessions,
                fixture.audits,
                fixture.throttle,
                fixture.tokenPairs,
                Clock.fixed(preciseNow, ZoneOffset.UTC)
        );

        assertDoesNotThrow(() -> service.refresh(new RefreshTokenCommand(
                "synthetic-refresh-token",
                CORRELATION_ID,
                SOURCE_ADDRESS
        )));
    }

    private static final class Fixture {
        private final InMemoryIdentityRepository identities = new InMemoryIdentityRepository();
        private final InMemorySessionRepository sessions = new InMemorySessionRepository();
        private final RecordingAuditRepository audits = new RecordingAuditRepository();
        private final StubPasswordService passwords = new StubPasswordService();
        private final RecordingThrottle throttle = new RecordingThrottle();
        private final StubTokenPairService tokenPairs = new StubTokenPairService();

        private ProvisionCustomerIdentityService provisionService() {
            return new ProvisionCustomerIdentityService(
                    identities,
                    audits,
                    passwords,
                    throttle,
                    CLOCK
            );
        }

        private LoginIdentityService loginService() {
            return new LoginIdentityService(
                    identities,
                    sessions,
                    audits,
                    passwords,
                    new RegistrationPasswordPolicy(),
                    AUTHENTICATION_POLICY,
                    throttle,
                    tokenPairs,
                    CLOCK
            );
        }

        private RefreshTokenService refreshService() {
            return new RefreshTokenService(
                    identities,
                    sessions,
                    audits,
                    throttle,
                    tokenPairs,
                    CLOCK
            );
        }

        private IdentityAccount addActiveIdentity(String loginIdentifier) {
            UUID identityId = UUID.randomUUID();
            IdentityAccount identity = IdentityAccount.provision(
                    identityId,
                    UUID.randomUUID(),
                    IdentityActorType.RETAIL_CUSTOMER,
                    loginIdentifier,
                    EncodedPassword.fromPasswordEncoder(ENCODED_PASSWORD),
                    AuthenticationActor.of(IdentityActorType.SERVICE_ACCOUNT, "synthetic-provisioner"),
                    CORRELATION_ID,
                    NOW.minusSeconds(2)
            );
            identity.enable(
                    AuthenticationActor.of(IdentityActorType.SERVICE_ACCOUNT, "synthetic-provisioner"),
                    CORRELATION_ID,
                    NOW.minusSeconds(1)
            );
            identity.releaseAuditEvents();
            return identities.save(identity);
        }
    }

    private static final class InMemoryIdentityRepository implements IdentityAccountRepository {
        private final Map<UUID, IdentityAccount> identities = new LinkedHashMap<>();

        @Override
        public boolean existsByLoginIdentifier(String loginIdentifier) {
            return identities.values().stream()
                    .anyMatch(identity -> identity.getLoginIdentifier().equals(loginIdentifier));
        }

        @Override
        public Optional<IdentityAccount> findByLoginIdentifierForUpdate(String loginIdentifier) {
            return identities.values().stream()
                    .filter(identity -> identity.getLoginIdentifier().equals(loginIdentifier))
                    .findFirst();
        }

        @Override
        public Optional<IdentityAccount> findById(UUID identityId) {
            return Optional.ofNullable(identities.get(identityId));
        }

        @Override
        public Optional<IdentityAccount> findByIdForUpdate(UUID identityId) {
            return findById(identityId);
        }

        @Override
        public Optional<IdentityAccount> findByActorTypeAndSubjectIdForUpdate(
                IdentityActorType actorType,
                UUID subjectId
        ) {
            return identities.values().stream()
                    .filter(identity -> identity.getActorType() == actorType)
                    .filter(identity -> identity.getSubjectId().equals(subjectId))
                    .findFirst();
        }

        @Override
        public IdentityAccount save(IdentityAccount identityAccount) {
            identities.put(identityAccount.getId(), identityAccount);
            return identityAccount;
        }
    }

    private static final class InMemorySessionRepository implements AuthenticationSessionRepository {
        private final Map<UUID, AuthenticationSession> sessions = new LinkedHashMap<>();

        @Override
        public Optional<AuthenticationSession> findById(UUID sessionId) {
            return Optional.ofNullable(sessions.get(sessionId));
        }

        @Override
        public Optional<AuthenticationSession> findByIdForUpdate(UUID sessionId) {
            return findById(sessionId);
        }

        @Override
        public AuthenticationSession save(AuthenticationSession authenticationSession) {
            sessions.put(authenticationSession.getId(), authenticationSession);
            return authenticationSession;
        }

        private AuthenticationSession onlySession() {
            assertEquals(1, sessions.size());
            return sessions.values().iterator().next();
        }
    }

    private static final class RecordingAuditRepository implements AuthenticationAuditRepository {
        private final List<AuthenticationAuditEvent> events = new ArrayList<>();

        @Override
        public void saveAll(Collection<AuthenticationAuditEvent> auditEvents) {
            events.addAll(auditEvents);
        }

        private List<AuthenticationAction> actions() {
            return events.stream().map(AuthenticationAuditEvent::getAction).toList();
        }
    }

    private static final class StubPasswordService implements PasswordService {
        private final List<String> encodedInputs = new ArrayList<>();
        private int unusableCredentialCount;
        private int matchCount;
        private int dummyMatchCount;

        @Override
        public EncodedPassword encode(String rawPassword) {
            encodedInputs.add(rawPassword);
            return EncodedPassword.fromPasswordEncoder(ENCODED_PASSWORD);
        }

        @Override
        public EncodedPassword createUnusableCredential() {
            unusableCredentialCount++;
            return EncodedPassword.fromPasswordEncoder(UNUSABLE_ENCODED_PASSWORD);
        }

        @Override
        public boolean matches(String rawPassword, String encodedPassword) {
            matchCount++;
            return RAW_PASSWORD.equals(rawPassword) && ENCODED_PASSWORD.equals(encodedPassword);
        }

        @Override
        public void performDummyMatch(String rawPassword) {
            dummyMatchCount++;
        }
    }

    private static final class RecordingThrottle implements AuthenticationThrottle {
        private String lastRegistrationSource;
        private String lastLoginIdentifier;

        @Override
        public void checkRegistration(String sourceAddress, Instant now) {
            lastRegistrationSource = sourceAddress;
        }

        @Override
        public void checkLogin(String sourceAddress, String normalizedLoginIdentifier, Instant now) {
            lastLoginIdentifier = normalizedLoginIdentifier;
        }

        @Override
        public void checkRefresh(String sourceAddress, Instant now) {
        }
    }

    private static final class StubTokenPairService implements TokenPairService {
        private final List<String> verifiedInputs = new ArrayList<>();
        private VerifiedRefreshToken verifiedRefreshToken;
        private int issueCount;

        @Override
        public IssuedTokenPair issuePair(
                IdentityAccount identityAccount,
                AuthenticationSession authenticationSession,
                Instant now
        ) {
            issueCount++;
            return new IssuedTokenPair(
                    identityAccount.getId(),
                    "synthetic-access-token-" + issueCount,
                    now.plus(Duration.ofMinutes(5)),
                    "synthetic-refresh-token-" + issueCount,
                    authenticationSession.getExpiresAt()
            );
        }

        @Override
        public VerifiedRefreshToken verifyRefreshToken(String refreshToken) {
            verifiedInputs.add(refreshToken);
            if (verifiedRefreshToken == null) {
                throw new InvalidRefreshTokenException();
            }
            return verifiedRefreshToken;
        }
    }
}
