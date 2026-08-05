package com.quinnbank.core.identity.infrastructure.security;

import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

public class IdentityJwtClaimValidator implements OAuth2TokenValidator<Jwt> {
    public static final String ACTOR_TYPE_CLAIM = "actor_type";
    public static final String SESSION_ID_CLAIM = "sid";
    public static final String TOKEN_USE_CLAIM = "token_use";
    public static final String ACCESS_TOKEN_USE = "access";
    public static final String REFRESH_TOKEN_USE = "refresh";

    private static final OAuth2Error INVALID_TOKEN = new OAuth2Error(
            "invalid_token",
            "The token claims are invalid.",
            null
    );

    private final String expectedAudience;
    private final String expectedTokenUse;
    private final Duration maximumLifetime;

    public IdentityJwtClaimValidator(
            String expectedAudience,
            String expectedTokenUse,
            Duration maximumLifetime
    ) {
        this.expectedAudience = requireText(expectedAudience, "expectedAudience");
        this.expectedTokenUse = requireText(expectedTokenUse, "expectedTokenUse");
        if (maximumLifetime == null || maximumLifetime.isNegative() || maximumLifetime.isZero()) {
            throw new IllegalArgumentException("maximumLifetime must be positive.");
        }
        this.maximumLifetime = maximumLifetime;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        try {
            List<String> audience = jwt.getAudience();
            UUID.fromString(jwt.getSubject());
            UUID.fromString(jwt.getId());
            UUID.fromString(jwt.getClaimAsString(SESSION_ID_CLAIM));
            IdentityActorType actorType = IdentityActorType.valueOf(jwt.getClaimAsString(ACTOR_TYPE_CLAIM));
            String tokenUse = jwt.getClaimAsString(TOKEN_USE_CLAIM);
            Duration lifetime = Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt());
            if (audience.size() != 1
                    || !expectedAudience.equals(audience.getFirst())
                    || !expectedTokenUse.equals(tokenUse)
                    || !isInteractiveActor(actorType)
                    || jwt.getIssuedAt() == null
                    || jwt.getExpiresAt() == null
                    || jwt.getNotBefore() == null
                    || !jwt.getNotBefore().equals(jwt.getIssuedAt())
                    || lifetime.isNegative()
                    || lifetime.isZero()
                    || lifetime.compareTo(maximumLifetime) > 0) {
                return OAuth2TokenValidatorResult.failure(INVALID_TOKEN);
            }
            return OAuth2TokenValidatorResult.success();
        } catch (RuntimeException exception) {
            return OAuth2TokenValidatorResult.failure(INVALID_TOKEN);
        }
    }

    private static boolean isInteractiveActor(IdentityActorType actorType) {
        return actorType == IdentityActorType.RETAIL_CUSTOMER
                || actorType == IdentityActorType.BUSINESS_CUSTOMER
                || actorType == IdentityActorType.BANK_EMPLOYEE
                || actorType == IdentityActorType.BACK_OFFICE_OPERATOR;
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " is required.");
        }
        return value;
    }
}
