package com.quinnbank.core.identity.infrastructure.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.quinnbank.core.identity.application.exception.InvalidRefreshTokenException;
import com.quinnbank.core.identity.application.exception.SigningKeyUnavailableException;
import com.quinnbank.core.identity.application.policy.AuthenticationTimestampPolicy;
import com.quinnbank.core.identity.application.port.JwtSigningKeyRepository;
import com.quinnbank.core.identity.application.port.TokenPairService;
import com.quinnbank.core.identity.application.result.IssuedTokenPair;
import com.quinnbank.core.identity.application.result.VerifiedRefreshToken;
import com.quinnbank.core.identity.domain.AuthenticationSession;
import com.quinnbank.core.identity.domain.IdentityAccount;
import com.quinnbank.core.identity.domain.JwtSigningKey;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import com.quinnbank.core.identity.infrastructure.configuration.IdentityAuthenticationProperties;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public class DatabaseBackedJwtTokenService implements TokenPairService {
    private static final String ACCESS_HEADER_TYPE = "at+jwt";
    private static final String REFRESH_HEADER_TYPE = "rt+jwt";
    private static final int MAX_COMPACT_TOKEN_LENGTH = 4_096;

    private final JwtSigningKeyRepository signingKeys;
    private final RsaSigningKeyMaterialGenerator signingMaterialGenerator;
    private final IdentityAuthenticationProperties properties;
    private final JwtDecoder refreshTokenDecoder;

    public DatabaseBackedJwtTokenService(
        JwtSigningKeyRepository signingKeys,
        RsaSigningKeyMaterialGenerator signingMaterialGenerator,
        IdentityAuthenticationProperties properties,
        JwtDecoder refreshTokenDecoder
    ) {
        this.signingKeys = signingKeys;
        this.signingMaterialGenerator = signingMaterialGenerator;
        this.properties = properties;
        this.refreshTokenDecoder = refreshTokenDecoder;
    }

    @Override
    public IssuedTokenPair issuePair(
        IdentityAccount identityAccount,
        AuthenticationSession authenticationSession,
        Instant now
    ) {
        requireIssueState(identityAccount, authenticationSession, now);
        Instant issuedAt = AuthenticationTimestampPolicy.jwtCompatible(now);
        Instant sessionExpiresAt = AuthenticationTimestampPolicy.jwtCompatible(
                authenticationSession.getExpiresAt()
        );
        if (!sessionExpiresAt.isAfter(issuedAt)) {
            throw new IllegalStateException("The authentication session has no JWT-compatible lifetime remaining.");
        }
        Instant accessExpiresAt = earlierOf(
            issuedAt.plus(requirePositive(properties.getAccessTokenTtl(), "accessTokenTtl")),
            sessionExpiresAt
        );
        Instant refreshExpiresAt = sessionExpiresAt;
        RsaSigningKeyMaterial material = signingMaterialGenerator.generate();
        if (material == null) {
            throw new SigningKeyUnavailableException();
        }

        try (material) {
            JwtEncoder encoder = signingEncoder(material);
            String accessToken = encode(
                encoder,
                material.keyId(),
                ACCESS_HEADER_TYPE,
                claims(
                    identityAccount,
                    authenticationSession,
                    UUID.randomUUID(),
                    IdentityJwtClaimValidator.ACCESS_TOKEN_USE,
                    requiredText(properties.getAccessAudience(), "accessAudience"),
                    issuedAt,
                    accessExpiresAt
                )
            );
            String refreshToken = encode(
                    encoder,
                    material.keyId(),
                    REFRESH_HEADER_TYPE,
                    claims(
                        identityAccount,
                        authenticationSession,
                        authenticationSession.getCurrentRefreshTokenId(),
                        IdentityJwtClaimValidator.REFRESH_TOKEN_USE,
                        requiredText(properties.getRefreshAudience(), "refreshAudience"),
                        issuedAt,
                        refreshExpiresAt
                    )
            );

            signingKeys.save(JwtSigningKey.register(
                material.keyId(),
                material.publicKey().getEncoded(),
                material.publicKeySha256(),
                issuedAt
            ));

            return new IssuedTokenPair(
                identityAccount.getId(),
                accessToken,
                accessExpiresAt,
                refreshToken,
                refreshExpiresAt
            );
        }
    }

    @Override
    public VerifiedRefreshToken verifyRefreshToken(String refreshToken) {
        if (refreshToken == null
                || refreshToken.length() < 100
                || refreshToken.length() > MAX_COMPACT_TOKEN_LENGTH) {
            throw new InvalidRefreshTokenException();
        }

        try {
            Jwt jwt = refreshTokenDecoder.decode(refreshToken);
            return new VerifiedRefreshToken(
                UUID.fromString(jwt.getSubject()),
                IdentityActorType.valueOf(
                        jwt.getClaimAsString(IdentityJwtClaimValidator.ACTOR_TYPE_CLAIM)
                ),
                UUID.fromString(jwt.getClaimAsString(IdentityJwtClaimValidator.SESSION_ID_CLAIM)),
                UUID.fromString(jwt.getId()),
                jwt.getIssuedAt(),
                jwt.getExpiresAt()
            );
        } catch (JwtException | IllegalArgumentException | NullPointerException exception) {
            throw new InvalidRefreshTokenException();
        }
    }

    private JwtClaimsSet claims(
        IdentityAccount identity,
        AuthenticationSession session,
        UUID tokenId,
        String tokenUse,
        String audience,
        Instant issuedAt,
        Instant expiresAt
    ) {
        return JwtClaimsSet
        .builder()
        .issuer(requiredText(properties.getIssuer(), "issuer"))
        .subject(identity.getId().toString())
        .audience(List.of(audience))
        .issuedAt(issuedAt)
        .notBefore(issuedAt)
        .expiresAt(expiresAt)
        .id(tokenId.toString())
        .claim(IdentityJwtClaimValidator.ACTOR_TYPE_CLAIM, identity.getActorType().name())
        .claim(IdentityJwtClaimValidator.SESSION_ID_CLAIM, session.getId().toString())
        .claim(IdentityJwtClaimValidator.TOKEN_USE_CLAIM, tokenUse)
        .build();
    }

    private static String encode(
            JwtEncoder encoder,
            String keyId,
            String headerType,
            JwtClaimsSet claims
    ) {
        try {
            JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(keyId)
                .type(headerType)
                .build();
            return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        } catch (JwtEncodingException exception) {
            throw new SigningKeyUnavailableException();
        }
    }

    private static JwtEncoder signingEncoder(RsaSigningKeyMaterial material) {
        RSAKey signingKey = new RSAKey.Builder(material.publicKey())
            .privateKey(material.privateKey())
            .keyID(material.keyId())
            .algorithm(JWSAlgorithm.RS256)
            .keyUse(KeyUse.SIGNATURE)
            .build();
        JWKSource<SecurityContext> signingKeySource = (selector, context) ->selector.select(new JWKSet(signingKey));
        return new NimbusJwtEncoder(signingKeySource);
    }

    private static void requireIssueState(
        IdentityAccount identity,
        AuthenticationSession session,
        Instant now
    ) {
        if (identity == null || session == null || now == null
                || !identity.getId().equals(session.getIdentityId())
                || !identity.canAuthenticate(now)
                || !session.isActive(now)) {
            throw new IllegalStateException("An active identity session is required for token issuance.");
        }
    }

    private static Duration requirePositive(Duration value, String fieldName) {
        if (value == null || value.isNegative() || value.isZero()) {
            throw new IllegalArgumentException(fieldName + " must be positive.");
        }
        return value;
    }

    private static String requiredText(String value, String fieldName) {
        if (value == null || value.isBlank() || value.length() > 255) {
            throw new IllegalArgumentException(fieldName + " is invalid.");
        }
        return value;
    }

    private static Instant earlierOf(Instant first, Instant second) {
        return first.isBefore(second) ? first : second;
    }
}
