package com.quinnbank.core.identity.infrastructure.security;

import com.quinnbank.core.identity.application.port.AuthenticationSessionRepository;
import com.quinnbank.core.identity.application.port.IdentityAccountRepository;
import com.quinnbank.core.identity.application.policy.AuthenticationTimestampPolicy;
import com.quinnbank.core.identity.domain.AuthenticationSession;
import com.quinnbank.core.identity.domain.IdentityAccount;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

public class AccessTokenStateValidator implements OAuth2TokenValidator<Jwt> {
    private static final OAuth2Error INVALID_TOKEN = new OAuth2Error(
        "invalid_token",
        "The token is no longer active.",
        null
    );

    private final IdentityAccountRepository identityAccounts;
    private final AuthenticationSessionRepository sessions;
    private final Clock clock;

    public AccessTokenStateValidator(
        IdentityAccountRepository identityAccounts,
        AuthenticationSessionRepository sessions,
        Clock clock
    ) {
        this.identityAccounts = identityAccounts;
        this.sessions = sessions;
        this.clock = clock;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        try {
            Instant now = clock.instant();
            UUID identityId = UUID.fromString(jwt.getSubject());
            UUID sessionId = UUID.fromString(jwt.getClaimAsString(IdentityJwtClaimValidator.SESSION_ID_CLAIM));
            IdentityAccount identity = identityAccounts.findById(identityId).orElse(null);
            AuthenticationSession session = sessions.findById(sessionId).orElse(null);
            if (identity == null
                    || session == null
                    || !identity.getId().equals(session.getIdentityId())
                    || !identity.canAuthenticate(now)
                    || !session.isActive(now)
                    || jwt.getIssuedAt() == null
                    || jwt.getExpiresAt() == null
                    || jwt.getIssuedAt().isBefore(
                    AuthenticationTimestampPolicy.jwtCompatible(session.getCreatedAt())
                )
                    || jwt.getExpiresAt().isAfter(
                        AuthenticationTimestampPolicy.jwtCompatible(session.getExpiresAt())
                )
                    || !identity.getActorType().name().equals(
                        jwt.getClaimAsString(IdentityJwtClaimValidator.ACTOR_TYPE_CLAIM)
                )
                    || jwt.getIssuedAt().isBefore(identity.getCredentialsChangedAt())) {
                return OAuth2TokenValidatorResult.failure(INVALID_TOKEN);
            }
            return OAuth2TokenValidatorResult.success();
        } catch (RuntimeException exception) {
            return OAuth2TokenValidatorResult.failure(INVALID_TOKEN);
        }
    }
}
