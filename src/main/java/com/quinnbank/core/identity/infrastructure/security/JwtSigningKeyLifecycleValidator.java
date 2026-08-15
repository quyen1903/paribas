package com.quinnbank.core.identity.infrastructure.security;

import com.quinnbank.core.identity.application.policy.AuthenticationTimestampPolicy;
import com.quinnbank.core.identity.application.port.JwtSigningKeyRepository;
import com.quinnbank.core.identity.domain.JwtSigningKey;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

public class JwtSigningKeyLifecycleValidator implements OAuth2TokenValidator<Jwt> {
    private static final OAuth2Error INVALID_TOKEN = new OAuth2Error(
        "invalid_token",
        "The token signing key lifecycle is invalid.",
        null
    );

    private final JwtSigningKeyRepository signingKeys;
    private final Clock clock;
    private final Duration clockSkew;

    public JwtSigningKeyLifecycleValidator(
            JwtSigningKeyRepository signingKeys,
            Clock clock,
            Duration clockSkew
    ) {
        this.signingKeys = signingKeys;
        this.clock = clock;
        if (clockSkew == null || clockSkew.isNegative() || clockSkew.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("clockSkew is invalid.");
        }
        this.clockSkew = clockSkew;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        try {
            Object headerKeyId = jwt.getHeaders().get("kid");
            Instant issuedAt = jwt.getIssuedAt();
            if (!(headerKeyId instanceof String keyId) || keyId.isBlank() || issuedAt == null) {
                return OAuth2TokenValidatorResult.failure(INVALID_TOKEN);
            }

            JwtSigningKey signingKey = signingKeys.findByKeyId(keyId).orElse(null);
            if (signingKey == null || !signingKey.canVerify(clock.instant().plus(clockSkew))) {
                return OAuth2TokenValidatorResult.failure(INVALID_TOKEN);
            }

            Instant keyCreatedAt = AuthenticationTimestampPolicy.jwtCompatible(signingKey.getCreatedAt());
            Instant verifyOnlyAt = signingKey.getVerifyOnlyAt() == null
                ? null
                : AuthenticationTimestampPolicy.jwtCompatible(signingKey.getVerifyOnlyAt());
            if (issuedAt.isBefore(keyCreatedAt)
                    || (verifyOnlyAt != null && issuedAt.isAfter(verifyOnlyAt))) {
                return OAuth2TokenValidatorResult.failure(INVALID_TOKEN);
            }
            return OAuth2TokenValidatorResult.success();
        } catch (RuntimeException exception) {
            return OAuth2TokenValidatorResult.failure(INVALID_TOKEN);
        }
    }
}
