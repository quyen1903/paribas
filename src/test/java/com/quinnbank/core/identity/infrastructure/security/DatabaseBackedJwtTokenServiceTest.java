package com.quinnbank.core.identity.infrastructure.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.quinnbank.core.identity.application.exception.InvalidRefreshTokenException;
import com.quinnbank.core.identity.application.policy.AuthenticationTimestampPolicy;
import com.quinnbank.core.identity.application.port.AuthenticationSessionRepository;
import com.quinnbank.core.identity.application.port.IdentityAccountRepository;
import com.quinnbank.core.identity.application.port.JwtSigningKeyRepository;
import com.quinnbank.core.identity.application.result.IssuedTokenPair;
import com.quinnbank.core.identity.application.result.VerifiedRefreshToken;
import com.quinnbank.core.identity.domain.AuthenticationActor;
import com.quinnbank.core.identity.domain.AuthenticationSession;
import com.quinnbank.core.identity.domain.EncodedPassword;
import com.quinnbank.core.identity.domain.IdentityAccount;
import com.quinnbank.core.identity.domain.JwtSigningKey;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import com.quinnbank.core.identity.domain.enums.JwtSigningAlgorithm;
import com.quinnbank.core.identity.domain.enums.JwtSigningKeyStatus;
import com.quinnbank.core.identity.infrastructure.configuration.IdentityAuthenticationProperties;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import javax.security.auth.DestroyFailedException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Base64;
import java.util.Deque;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DatabaseBackedJwtTokenServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-04T12:00:00.987654321Z");
    private static final Instant JWT_NOW = AuthenticationTimestampPolicy.jwtCompatible(NOW);
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String FIRST_KEY_ID = "synthetic-ephemeral-rsa-key-001";
    private static final String SECOND_KEY_ID = "synthetic-ephemeral-rsa-key-002";
    private static final String FAILED_ISSUANCE_KEY_ID = "synthetic-ephemeral-rsa-key-failed";
    private static final String ISSUER = "https://identity.example.invalid";
    private static final String ACCESS_AUDIENCE = "synthetic-core-api";
    private static final String REFRESH_AUDIENCE = "synthetic-core-refresh";
    private static final String ENCODED_PASSWORD = "$2b$12$" + "b".repeat(53);

    private static TestSigningMaterial firstSigningMaterial;
    private static TestSigningMaterial secondSigningMaterial;
    private static TestSigningMaterial failedIssuanceSigningMaterial;
    private static RSAPublicKey attackerPublicKey;

    @BeforeAll
    static void generateEphemeralSigningMaterial() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3_072);
        firstSigningMaterial = testSigningMaterial(generator, FIRST_KEY_ID);
        secondSigningMaterial = testSigningMaterial(generator, SECOND_KEY_ID);
        failedIssuanceSigningMaterial = testSigningMaterial(generator, FAILED_ISSUANCE_KEY_ID);

        KeyPair attackerKeyPair = generator.generateKeyPair();
        attackerPublicKey = (RSAPublicKey) attackerKeyPair.getPublic();
    }

    @Test
    void rejectsDatabasePublicMaterialWhoseStoredFingerprintDoesNotMatch() {
        JwtSigningKeyRepository signingKeys = mock(JwtSigningKeyRepository.class);
        JwtSigningKey substitutedKey = mock(JwtSigningKey.class);
        when(signingKeys.findByKeyId(FIRST_KEY_ID)).thenReturn(Optional.of(substitutedKey));
        when(substitutedKey.getAlgorithm()).thenReturn(JwtSigningAlgorithm.RS256);
        when(substitutedKey.canVerify(NOW)).thenReturn(true);
        when(substitutedKey.getPublicKeyDer()).thenReturn(attackerPublicKey.getEncoded());
        when(substitutedKey.getPublicKeySha256()).thenReturn(firstSigningMaterial.material().publicKeySha256());
        DatabaseJwkSource source = new DatabaseJwkSource(signingKeys, CLOCK, Duration.ZERO);
        JWKSelector selector = new JWKSelector(new JWKMatcher.Builder()
                .keyID(FIRST_KEY_ID)
                .algorithm(JWSAlgorithm.RS256)
                .build());

        assertTrue(source.get(selector, null).isEmpty());
    }

    @Test
    void keyLookupHonorsConfiguredClockSkewWhenVerifierClockTrailsIssuer() throws Exception {
        JwtSigningKeyRepository signingKeys = mock(JwtSigningKeyRepository.class);
        JwtSigningKey signingKey = mock(JwtSigningKey.class);
        String fingerprint = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(attackerPublicKey.getEncoded())
        );
        when(signingKeys.findByKeyId(FIRST_KEY_ID)).thenReturn(Optional.of(signingKey));
        when(signingKey.getKeyId()).thenReturn(FIRST_KEY_ID);
        when(signingKey.getAlgorithm()).thenReturn(JwtSigningAlgorithm.RS256);
        when(signingKey.canVerify(NOW.plusSeconds(15))).thenReturn(true);
        when(signingKey.getPublicKeyDer()).thenReturn(attackerPublicKey.getEncoded());
        when(signingKey.getPublicKeySha256()).thenReturn(fingerprint);
        DatabaseJwkSource source = new DatabaseJwkSource(
                signingKeys,
                Clock.fixed(NOW.minusSeconds(15), ZoneOffset.UTC),
                Duration.ofSeconds(30)
        );
        JWKSelector selector = new JWKSelector(new JWKMatcher.Builder()
                .keyID(FIRST_KEY_ID)
                .algorithm(JWSAlgorithm.RS256)
                .build());

        assertFalse(source.get(selector, null).isEmpty());
    }

    @Test
    void doesNotPersistPublicKeyWhenBothTokensWereNotSuccessfullyEncoded() {
        IdentityAuthenticationProperties properties = properties();
        properties.setRefreshAudience(" ");
        InMemorySigningKeyRepository signingKeys = new InMemorySigningKeyRepository();
        QueueSigningKeyMaterialGenerator generator = new QueueSigningKeyMaterialGenerator(
                failedIssuanceSigningMaterial.material()
        );
        IdentityAccount identity = activeIdentity();
        AuthenticationSession session = AuthenticationSession.open(
                UUID.fromString("10000000-0000-0000-0000-000000000011"),
                identity.getId(),
                UUID.fromString("20000000-0000-0000-0000-000000000012"),
                NOW.plus(Duration.ofHours(1)),
                NOW.minusSeconds(1)
        );
        DatabaseBackedJwtTokenService tokenService = new DatabaseBackedJwtTokenService(
                signingKeys,
                generator,
                properties,
                mock(JwtDecoder.class)
        );

        assertThrows(IllegalArgumentException.class, () -> tokenService.issuePair(identity, session, NOW));

        assertAll(
                () -> assertTrue(signingKeys.stored.isEmpty()),
                () -> assertEquals(1, failedIssuanceSigningMaterial.privateKey().destructionAttempts()),
                () -> assertThrows(
                        IllegalStateException.class,
                        failedIssuanceSigningMaterial.material()::privateKey
                )
        );
    }

    @Test
    void issuesEachTokenPairWithDistinctEphemeralMaterialAndRetainsPublicVerification() {
        IdentityAuthenticationProperties properties = properties();
        InMemorySigningKeyRepository signingKeys = new InMemorySigningKeyRepository();
        QueueSigningKeyMaterialGenerator generator = new QueueSigningKeyMaterialGenerator(
                firstSigningMaterial.material(),
                secondSigningMaterial.material()
        );

        IdentityAccount identity = activeIdentity();
        AuthenticationSession session = AuthenticationSession.open(
                UUID.fromString("10000000-0000-0000-0000-000000000001"),
                identity.getId(),
                UUID.fromString("20000000-0000-0000-0000-000000000002"),
                NOW.plus(Duration.ofHours(1)),
                NOW.minusSeconds(1)
        );
        SingleIdentityRepository identities = new SingleIdentityRepository(identity);
        SingleSessionRepository sessions = new SingleSessionRepository(session);
        DatabaseJwkSource jwkSource = new DatabaseJwkSource(signingKeys, CLOCK, Duration.ZERO);
        JwtDecoder refreshDecoder = IdentityJwtDecoderFactory.refreshTokenDecoder(
                jwkSource,
                properties,
                signingKeys,
                CLOCK
        );
        DatabaseBackedJwtTokenService tokenService = new DatabaseBackedJwtTokenService(
                signingKeys,
                generator,
                properties,
                refreshDecoder
        );

        IssuedTokenPair firstPair = tokenService.issuePair(identity, session, NOW);
        IssuedTokenPair secondPair = tokenService.issuePair(identity, session, NOW);
        JwtDecoder accessDecoder = IdentityJwtDecoderFactory.accessTokenDecoder(
                jwkSource,
                properties,
                identities,
                sessions,
                signingKeys,
                CLOCK
        );
        Jwt firstAccess = accessDecoder.decode(firstPair.accessToken());
        Jwt firstRefresh = refreshDecoder.decode(firstPair.refreshToken());
        Jwt secondAccess = accessDecoder.decode(secondPair.accessToken());
        Jwt secondRefresh = refreshDecoder.decode(secondPair.refreshToken());
        VerifiedRefreshToken verifiedFirstRefresh = tokenService.verifyRefreshToken(firstPair.refreshToken());
        JwtSigningKey firstStoredKey = signingKeys.findByKeyId(FIRST_KEY_ID).orElseThrow();
        JwtSigningKey secondStoredKey = signingKeys.findByKeyId(SECOND_KEY_ID).orElseThrow();

        assertAll(
                () -> assertEquals(identity.getId().toString(), firstAccess.getSubject()),
                () -> assertEquals(ISSUER, firstAccess.getIssuer().toString()),
                () -> assertEquals(java.util.List.of(ACCESS_AUDIENCE), firstAccess.getAudience()),
                () -> assertEquals(JWT_NOW, firstAccess.getIssuedAt()),
                () -> assertEquals(JWT_NOW, firstAccess.getNotBefore()),
                () -> assertEquals(JWT_NOW.plus(Duration.ofMinutes(5)), firstAccess.getExpiresAt()),
                () -> assertEquals(
                        "access",
                        firstAccess.getClaimAsString(IdentityJwtClaimValidator.TOKEN_USE_CLAIM)
                ),
                () -> assertEquals(
                        IdentityActorType.RETAIL_CUSTOMER.name(),
                        firstAccess.getClaimAsString(IdentityJwtClaimValidator.ACTOR_TYPE_CLAIM)
                ),
                () -> assertEquals(
                        session.getId().toString(),
                        firstAccess.getClaimAsString(IdentityJwtClaimValidator.SESSION_ID_CLAIM)
                ),
                () -> assertEquals("RS256", firstAccess.getHeaders().get("alg")),
                () -> assertEquals("at+jwt", firstAccess.getHeaders().get("typ")),
                () -> assertEquals(FIRST_KEY_ID, firstAccess.getHeaders().get("kid")),
                () -> assertEquals(firstAccess.getHeaders().get("kid"), firstRefresh.getHeaders().get("kid")),
                () -> assertEquals(secondAccess.getHeaders().get("kid"), secondRefresh.getHeaders().get("kid")),
                () -> assertNotEquals(firstAccess.getHeaders().get("kid"), secondAccess.getHeaders().get("kid")),
                () -> assertEquals(identity.getId(), verifiedFirstRefresh.identityId()),
                () -> assertEquals(session.getId(), verifiedFirstRefresh.sessionId()),
                () -> assertEquals(session.getCurrentRefreshTokenId(), verifiedFirstRefresh.tokenId()),
                () -> assertEquals(
                        AuthenticationTimestampPolicy.jwtCompatible(session.getExpiresAt()),
                        verifiedFirstRefresh.expiresAt()
                ),
                () -> assertNotNull(firstStoredKey),
                () -> assertNotNull(secondStoredKey),
                () -> assertEquals(JwtSigningKeyStatus.VERIFY_ONLY, firstStoredKey.getStatus()),
                () -> assertEquals(JwtSigningKeyStatus.VERIFY_ONLY, secondStoredKey.getStatus()),
                () -> assertArrayEquals(
                        firstSigningMaterial.material().publicKey().getEncoded(),
                        firstStoredKey.getPublicKeyDer()
                ),
                () -> assertArrayEquals(
                        secondSigningMaterial.material().publicKey().getEncoded(),
                        secondStoredKey.getPublicKeyDer()
                ),
                () -> assertFalse(Arrays.equals(firstStoredKey.getPublicKeyDer(), secondStoredKey.getPublicKeyDer())),
                () -> assertFalse(Arrays.equals(
                        firstSigningMaterial.privateKeyDer(),
                        firstStoredKey.getPublicKeyDer()
                )),
                () -> assertTrue(Arrays.stream(JwtSigningKey.class.getDeclaredFields())
                        .noneMatch(field -> PrivateKey.class.isAssignableFrom(field.getType()))),
                () -> assertEquals(1, firstSigningMaterial.privateKey().destructionAttempts()),
                () -> assertEquals(1, secondSigningMaterial.privateKey().destructionAttempts()),
                () -> assertFalse(firstSigningMaterial.material().toString()
                        .contains(firstSigningMaterial.privateKeyBase64())),
                () -> assertFalse(firstStoredKey.toString().contains(firstSigningMaterial.privateKeyBase64())),
                () -> assertFalse(session.toString().contains(firstPair.accessToken())),
                () -> assertFalse(session.toString().contains(firstPair.refreshToken())),
                () -> assertFalse(firstPair.toString().contains(firstPair.accessToken())),
                () -> assertFalse(firstPair.toString().contains(firstPair.refreshToken()))
        );

        assertThrows(JwtException.class, () -> accessDecoder.decode(firstPair.refreshToken()));
        assertThrows(
                InvalidRefreshTokenException.class,
                () -> tokenService.verifyRefreshToken(firstPair.accessToken())
        );
        assertThrows(JwtException.class, () -> accessDecoder.decode(tamperSignature(firstPair.accessToken())));

        IdentityAuthenticationProperties sharedAudienceProperties = properties();
        sharedAudienceProperties.setAccessAudience(REFRESH_AUDIENCE);
        JwtDecoder typeCheckingAccessDecoder = IdentityJwtDecoderFactory.accessTokenDecoder(
                jwkSource,
                sharedAudienceProperties,
                identities,
                sessions,
                signingKeys,
                CLOCK
        );
        assertThrows(JwtException.class, () -> typeCheckingAccessDecoder.decode(firstPair.refreshToken()));

        session.revoke("SYNTHETIC_TEST_REVOCATION", NOW.plusSeconds(1));
        assertThrows(JwtException.class, () -> accessDecoder.decode(firstPair.accessToken()));
    }

    private static IdentityAuthenticationProperties properties() {
        IdentityAuthenticationProperties properties = new IdentityAuthenticationProperties();
        properties.setIssuer(ISSUER);
        properties.setAccessAudience(ACCESS_AUDIENCE);
        properties.setRefreshAudience(REFRESH_AUDIENCE);
        properties.setAccessTokenTtl(Duration.ofMinutes(5));
        properties.setRefreshTokenTtl(Duration.ofDays(7));
        properties.setClockSkew(Duration.ZERO);
        return properties;
    }

    private static IdentityAccount activeIdentity() {
        UUID identityId = UUID.fromString("30000000-0000-0000-0000-000000000003");
        IdentityAccount identity = IdentityAccount.provision(
                identityId,
                identityId,
                IdentityActorType.RETAIL_CUSTOMER,
                "jwt-user@example.invalid",
                EncodedPassword.fromPasswordEncoder(ENCODED_PASSWORD),
                AuthenticationActor.of(IdentityActorType.SERVICE_ACCOUNT, "synthetic-provisioner"),
                "jwt-test-correlation",
                NOW.minusSeconds(2)
        );
        identity.enable(
                AuthenticationActor.of(IdentityActorType.SERVICE_ACCOUNT, "synthetic-provisioner"),
                "jwt-test-correlation",
                NOW.minusSeconds(1)
        );
        identity.releaseAuditEvents();
        return identity;
    }

    private static TestSigningMaterial testSigningMaterial(
            KeyPairGenerator generator,
            String keyId
    ) throws Exception {
        KeyPair keyPair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        DestructionTrackingRsaPrivateKey privateKey = new DestructionTrackingRsaPrivateKey(
                (RSAPrivateKey) keyPair.getPrivate()
        );
        String fingerprint = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded())
        );
        byte[] privateKeyDer = privateKey.getEncoded().clone();
        return new TestSigningMaterial(
                new RsaSigningKeyMaterial(keyId, publicKey, privateKey, fingerprint),
                privateKey,
                privateKeyDer,
                Base64.getEncoder().encodeToString(privateKeyDer)
        );
    }

    private static String tamperSignature(String compactToken) {
        char last = compactToken.charAt(compactToken.length() - 1);
        char replacement = last == 'A' ? 'B' : 'A';
        return compactToken.substring(0, compactToken.length() - 1) + replacement;
    }

    private static final class InMemorySigningKeyRepository implements JwtSigningKeyRepository {
        private final Map<String, JwtSigningKey> stored = new LinkedHashMap<>();

        @Override
        public Optional<JwtSigningKey> findByKeyId(String keyId) {
            return Optional.ofNullable(stored.get(keyId));
        }

        @Override
        public JwtSigningKey save(JwtSigningKey signingKey) {
            stored.put(signingKey.getKeyId(), signingKey);
            return signingKey;
        }
    }

    private static final class QueueSigningKeyMaterialGenerator implements RsaSigningKeyMaterialGenerator {
        private final Deque<RsaSigningKeyMaterial> materials;

        private QueueSigningKeyMaterialGenerator(RsaSigningKeyMaterial... materials) {
            this.materials = new ArrayDeque<>(java.util.List.of(materials));
        }

        @Override
        public RsaSigningKeyMaterial generate() {
            return materials.removeFirst();
        }
    }

    private record TestSigningMaterial(
            RsaSigningKeyMaterial material,
            DestructionTrackingRsaPrivateKey privateKey,
            byte[] privateKeyDer,
            String privateKeyBase64
    ) {
    }

    private static final class DestructionTrackingRsaPrivateKey implements RSAPrivateKey {
        private final RSAPrivateKey delegate;
        private int destructionAttempts;

        private DestructionTrackingRsaPrivateKey(RSAPrivateKey delegate) {
            this.delegate = delegate;
        }

        @Override
        public BigInteger getPrivateExponent() {
            return delegate.getPrivateExponent();
        }

        @Override
        public BigInteger getModulus() {
            return delegate.getModulus();
        }

        @Override
        public AlgorithmParameterSpec getParams() {
            return delegate.getParams();
        }

        @Override
        public String getAlgorithm() {
            return delegate.getAlgorithm();
        }

        @Override
        public String getFormat() {
            return delegate.getFormat();
        }

        @Override
        public byte[] getEncoded() {
            return delegate.getEncoded();
        }

        @Override
        public void destroy() throws DestroyFailedException {
            destructionAttempts++;
            delegate.destroy();
        }

        @Override
        public boolean isDestroyed() {
            return delegate.isDestroyed();
        }

        private int destructionAttempts() {
            return destructionAttempts;
        }
    }

    private static final class SingleIdentityRepository implements IdentityAccountRepository {
        private final IdentityAccount identity;

        private SingleIdentityRepository(IdentityAccount identity) {
            this.identity = identity;
        }

        @Override
        public boolean existsByLoginIdentifier(String loginIdentifier) {
            return identity.getLoginIdentifier().equals(loginIdentifier);
        }

        @Override
        public Optional<IdentityAccount> findByLoginIdentifierForUpdate(String loginIdentifier) {
            return existsByLoginIdentifier(loginIdentifier) ? Optional.of(identity) : Optional.empty();
        }

        @Override
        public Optional<IdentityAccount> findById(UUID identityId) {
            return identity.getId().equals(identityId) ? Optional.of(identity) : Optional.empty();
        }

        @Override
        public Optional<IdentityAccount> findByIdForUpdate(UUID identityId) {
            return findById(identityId);
        }

        @Override
        public IdentityAccount save(IdentityAccount identityAccount) {
            throw new UnsupportedOperationException("This test repository is read-only.");
        }
    }

    private static final class SingleSessionRepository implements AuthenticationSessionRepository {
        private final AuthenticationSession session;

        private SingleSessionRepository(AuthenticationSession session) {
            this.session = session;
        }

        @Override
        public Optional<AuthenticationSession> findById(UUID sessionId) {
            return session.getId().equals(sessionId) ? Optional.of(session) : Optional.empty();
        }

        @Override
        public Optional<AuthenticationSession> findByIdForUpdate(UUID sessionId) {
            return findById(sessionId);
        }

        @Override
        public AuthenticationSession save(AuthenticationSession authenticationSession) {
            throw new UnsupportedOperationException("This test repository is read-only.");
        }
    }
}
