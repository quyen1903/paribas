package com.quinnbank.core.identity.infrastructure.security;

import com.quinnbank.core.identity.application.port.AuthenticationSessionRepository;
import com.quinnbank.core.identity.application.port.IdentityAccountRepository;
import com.quinnbank.core.identity.application.port.JwtSigningKeyRepository;
import com.quinnbank.core.identity.infrastructure.configuration.IdentityAuthenticationProperties;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public final class IdentityJwtDecoderFactory {
    private static final String ACCESS_HEADER_TYPE = "at+jwt";
    private static final String REFRESH_HEADER_TYPE = "rt+jwt";

    private IdentityJwtDecoderFactory() {
    }

    public static JwtDecoder accessTokenDecoder(
        DatabaseJwkSource jwkSource,
        IdentityAuthenticationProperties properties,
        IdentityAccountRepository identityAccounts,
        AuthenticationSessionRepository sessions,
        JwtSigningKeyRepository signingKeys,
        Clock clock
    ) {
        List<OAuth2TokenValidator<Jwt>> validators = baseValidators(
            properties,
            properties.getAccessAudience(),
            IdentityJwtClaimValidator.ACCESS_TOKEN_USE,
            ACCESS_HEADER_TYPE,
            properties.getAccessTokenTtl(),
            signingKeys,
            clock
        );
        validators.add(new AccessTokenStateValidator(identityAccounts, sessions, clock));
        return decoder(jwkSource, validators);
    }

    public static JwtDecoder refreshTokenDecoder(
        DatabaseJwkSource jwkSource,
        IdentityAuthenticationProperties properties,
        JwtSigningKeyRepository signingKeys,
        Clock clock
    ) {
        return decoder(
                jwkSource,
                baseValidators(
                    properties,
                    properties.getRefreshAudience(),
                    IdentityJwtClaimValidator.REFRESH_TOKEN_USE,
                    REFRESH_HEADER_TYPE,
                    properties.getRefreshTokenTtl(),
                    signingKeys,
                    clock
                )
        );
    }

    private static JwtDecoder decoder(
            DatabaseJwkSource jwkSource,
            List<OAuth2TokenValidator<Jwt>> validators
    ) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder
            .withJwkSource(jwkSource)
            .jwsAlgorithm(SignatureAlgorithm.RS256)
            .build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
        return decoder;
    }

    private static List<OAuth2TokenValidator<Jwt>> baseValidators(
        IdentityAuthenticationProperties properties,
        String audience,
        String tokenUse,
        String headerType,
        Duration maximumLifetime,
        JwtSigningKeyRepository signingKeys,
        Clock clock
    ) {
        String issuer = requireText(properties.getIssuer(), "issuer");
        String requiredAudience = requireText(audience, "audience");
        Duration clockSkew = requireClockSkew(properties.getClockSkew());

        JwtTimestampValidator timestamps = new JwtTimestampValidator(clockSkew);
        timestamps.setClock(clock);
        timestamps.setAllowEmptyExpiryClaim(false);
        timestamps.setAllowEmptyNotBeforeClaim(false);

        JwtTypeValidator type = new JwtTypeValidator(headerType);
        type.setAllowEmpty(false);

        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(timestamps);
        validators.add(new JwtIssuerValidator(issuer));
        validators.add(type);
        validators.add(new IdentityJwtClaimValidator(requiredAudience, tokenUse, maximumLifetime));
        validators.add(new JwtSigningKeyLifecycleValidator(signingKeys, clock, clockSkew));
        return validators;
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank() || value.length() > 255) {
            throw new IllegalArgumentException(fieldName + " is invalid.");
        }
        return value;
    }

    private static Duration requireClockSkew(Duration value) {
        if (value == null || value.isNegative() || value.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("clockSkew is invalid.");
        }
        return value;
    }
}
