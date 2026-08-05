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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DatabaseBackedJwtTokenServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-04T12:00:00.987654321Z");
    private static final Instant JWT_NOW = AuthenticationTimestampPolicy.jwtCompatible(NOW);
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String KEY_ID = "synthetic-rsa-key-2026-08";
    private static final String ISSUER = "https://identity.example.invalid";
    private static final String ACCESS_AUDIENCE = "synthetic-core-api";
    private static final String REFRESH_AUDIENCE = "synthetic-core-refresh";
    private static final String ENCODED_PASSWORD = "$2b$12$" + "b".repeat(53);

    private static RsaSigningKeyMaterial signingMaterial;
    private static RSAPublicKey attackerPublicKey;

    @BeforeAll
    static void generateEphemeralSigningMaterial() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3_072);
        KeyPair keyPair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        String fingerprint = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded())
        );
        signingMaterial = new RsaSigningKeyMaterial(KEY_ID, publicKey, privateKey, fingerprint);

        KeyPair attackerKeyPair = generator.generateKeyPair();
        attackerPublicKey = (RSAPublicKey) attackerKeyPair.getPublic();
    }

    @Test
    void rejectsDatabasePublicMaterialThatDoesNotMatchItsTrustedFingerprint() {
        JwtSigningKeyRepository signingKeys = mock(JwtSigningKeyRepository.class);
        ExternalRsaSigningKeyMaterialProvider keyProvider = mock(ExternalRsaSigningKeyMaterialProvider.class);
        JwtSigningKey substitutedKey = mock(JwtSigningKey.class);
        when(signingKeys.findByKeyId(KEY_ID)).thenReturn(Optional.of(substitutedKey));
        when(substitutedKey.getAlgorithm()).thenReturn(JwtSigningAlgorithm.RS256);
        when(substitutedKey.canVerify(NOW)).thenReturn(true);
        when(substitutedKey.getPublicKeyDer()).thenReturn(attackerPublicKey.getEncoded());
        when(substitutedKey.getPublicKeySha256()).thenReturn(signingMaterial.publicKeySha256());
        when(keyProvider.trustedPublicKeyFingerprints()).thenReturn(Set.of(signingMaterial.publicKeySha256()));
        DatabaseJwkSource source = new DatabaseJwkSource(signingKeys, keyProvider, CLOCK);
        JWKSelector selector = new JWKSelector(new JWKMatcher.Builder()
                .keyID(KEY_ID)
                .algorithm(JWSAlgorithm.RS256)
                .build());

        assertTrue(source.get(selector, null).isEmpty());
    }

    @Test
    void issuesSignedTypedTokenPairAndUsesOnlyStoredPublicMaterialForValidation() {
        IdentityAuthenticationProperties properties = properties();
        InMemorySigningKeyRepository signingKeys = new InMemorySigningKeyRepository();
        ExternalRsaSigningKeyMaterialProvider keyProvider = mock(ExternalRsaSigningKeyMaterialProvider.class);
        when(keyProvider.currentSigningKey()).thenReturn(signingMaterial);
        when(keyProvider.trustedPublicKeyFingerprints()).thenReturn(Set.of(signingMaterial.publicKeySha256()));

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
        DatabaseJwkSource jwkSource = new DatabaseJwkSource(signingKeys, keyProvider, CLOCK);
        JwtDecoder refreshDecoder = IdentityJwtDecoderFactory.refreshTokenDecoder(
                jwkSource,
                properties,
                signingKeys,
                CLOCK
        );
        DatabaseBackedJwtTokenService tokenService = new DatabaseBackedJwtTokenService(
                signingKeys,
                keyProvider,
                properties,
                refreshDecoder
        );

        IssuedTokenPair pair = tokenService.issuePair(identity, session, NOW);
        JwtDecoder accessDecoder = IdentityJwtDecoderFactory.accessTokenDecoder(
                jwkSource,
                properties,
                identities,
                sessions,
                signingKeys,
                CLOCK
        );
        Jwt access = accessDecoder.decode(pair.accessToken());
        VerifiedRefreshToken refresh = tokenService.verifyRefreshToken(pair.refreshToken());
        JwtSigningKey storedKey = signingKeys.stored;

        assertAll(
                () -> assertEquals(identity.getId().toString(), access.getSubject()),
                () -> assertEquals(ISSUER, access.getIssuer().toString()),
                () -> assertEquals(java.util.List.of(ACCESS_AUDIENCE), access.getAudience()),
                () -> assertEquals(JWT_NOW, access.getIssuedAt()),
                () -> assertEquals(JWT_NOW, access.getNotBefore()),
                () -> assertEquals(JWT_NOW.plus(Duration.ofMinutes(5)), access.getExpiresAt()),
                () -> assertEquals("access", access.getClaimAsString(IdentityJwtClaimValidator.TOKEN_USE_CLAIM)),
                () -> assertEquals(
                        IdentityActorType.RETAIL_CUSTOMER.name(),
                        access.getClaimAsString(IdentityJwtClaimValidator.ACTOR_TYPE_CLAIM)
                ),
                () -> assertEquals(
                        session.getId().toString(),
                        access.getClaimAsString(IdentityJwtClaimValidator.SESSION_ID_CLAIM)
                ),
                () -> assertEquals("RS256", access.getHeaders().get("alg")),
                () -> assertEquals("at+jwt", access.getHeaders().get("typ")),
                () -> assertEquals(KEY_ID, access.getHeaders().get("kid")),
                () -> assertEquals(identity.getId(), refresh.identityId()),
                () -> assertEquals(session.getId(), refresh.sessionId()),
                () -> assertEquals(session.getCurrentRefreshTokenId(), refresh.tokenId()),
                () -> assertEquals(
                        AuthenticationTimestampPolicy.jwtCompatible(session.getExpiresAt()),
                        refresh.expiresAt()
                ),
                () -> assertNotNull(storedKey),
                () -> assertEquals(JwtSigningKeyStatus.ACTIVE, storedKey.getStatus()),
                () -> assertArrayEquals(signingMaterial.publicKey().getEncoded(), storedKey.getPublicKeyDer()),
                () -> assertFalse(Arrays.equals(
                        signingMaterial.privateKey().getEncoded(),
                        storedKey.getPublicKeyDer()
                )),
                () -> assertTrue(Arrays.stream(JwtSigningKey.class.getDeclaredFields())
                        .noneMatch(field -> PrivateKey.class.isAssignableFrom(field.getType()))),
                () -> assertFalse(signingMaterial.toString().contains(privateKeyBase64())),
                () -> assertFalse(storedKey.toString().contains(privateKeyBase64())),
                () -> assertFalse(session.toString().contains(pair.accessToken())),
                () -> assertFalse(session.toString().contains(pair.refreshToken())),
                () -> assertFalse(pair.toString().contains(pair.accessToken())),
                () -> assertFalse(pair.toString().contains(pair.refreshToken()))
        );

        assertThrows(JwtException.class, () -> accessDecoder.decode(pair.refreshToken()));
        assertThrows(InvalidRefreshTokenException.class, () -> tokenService.verifyRefreshToken(pair.accessToken()));
        assertThrows(JwtException.class, () -> accessDecoder.decode(tamperSignature(pair.accessToken())));

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
        assertThrows(JwtException.class, () -> typeCheckingAccessDecoder.decode(pair.refreshToken()));

        session.revoke("SYNTHETIC_TEST_REVOCATION", NOW.plusSeconds(1));
        assertThrows(JwtException.class, () -> accessDecoder.decode(pair.accessToken()));
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

    private static String privateKeyBase64() {
        return Base64.getEncoder().encodeToString(signingMaterial.privateKey().getEncoded());
    }

    private static String tamperSignature(String compactToken) {
        char last = compactToken.charAt(compactToken.length() - 1);
        char replacement = last == 'A' ? 'B' : 'A';
        return compactToken.substring(0, compactToken.length() - 1) + replacement;
    }

    private static final class InMemorySigningKeyRepository implements JwtSigningKeyRepository {
        private JwtSigningKey stored;

        @Override
        public Optional<JwtSigningKey> findByKeyId(String keyId) {
            return stored != null && stored.getKeyId().equals(keyId) ? Optional.of(stored) : Optional.empty();
        }

        @Override
        public Optional<JwtSigningKey> findActiveForUpdate() {
            return stored != null && stored.getStatus() == JwtSigningKeyStatus.ACTIVE
                    ? Optional.of(stored)
                    : Optional.empty();
        }

        @Override
        public JwtSigningKey save(JwtSigningKey signingKey) {
            stored = signingKey;
            return signingKey;
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
