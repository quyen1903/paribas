package com.quinnbank.core.identity.infrastructure.security;

import com.quinnbank.core.identity.application.port.JwtSigningKeyRepository;
import com.quinnbank.core.identity.domain.JwtSigningKey;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IdentityJwtValidatorsTest {
    private static final Instant NOW = Instant.parse("2026-08-04T12:00:00Z");
    private static final String AUDIENCE = "synthetic-api";

    @Test
    void rejectsTokenLifetimeLongerThanTheConfiguredMaximum() {
        IdentityJwtClaimValidator validator = new IdentityJwtClaimValidator(
                AUDIENCE,
                IdentityJwtClaimValidator.ACCESS_TOKEN_USE,
                Duration.ofMinutes(5)
        );

        assertFalse(validator.validate(token(NOW, NOW.plusSeconds(300))).hasErrors());
        assertTrue(validator.validate(token(NOW, NOW.plusSeconds(301))).hasErrors());
    }

    @Test
    void verifyOnlyKeyAcceptsPreviouslyIssuedTokenButRejectsNewIssuance() {
        JwtSigningKeyRepository signingKeys = mock(JwtSigningKeyRepository.class);
        JwtSigningKey signingKey = mock(JwtSigningKey.class);
        when(signingKeys.findByKeyId("retired-key")).thenReturn(Optional.of(signingKey));
        when(signingKey.canVerify(NOW.plusSeconds(1))).thenReturn(true);
        when(signingKey.getCreatedAt()).thenReturn(NOW.minusSeconds(60));
        when(signingKey.getVerifyOnlyAt()).thenReturn(NOW);
        JwtSigningKeyLifecycleValidator validator = new JwtSigningKeyLifecycleValidator(
                signingKeys,
                Clock.fixed(NOW.plusSeconds(1), ZoneOffset.UTC)
        );

        assertFalse(validator.validate(lifecycleToken(NOW.minusSeconds(1))).hasErrors());
        assertTrue(validator.validate(lifecycleToken(NOW.plusSeconds(1))).hasErrors());
    }

    private static Jwt token(Instant issuedAt, Instant expiresAt) {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getAudience()).thenReturn(List.of(AUDIENCE));
        when(jwt.getSubject()).thenReturn(UUID.randomUUID().toString());
        when(jwt.getId()).thenReturn(UUID.randomUUID().toString());
        when(jwt.getClaimAsString(IdentityJwtClaimValidator.SESSION_ID_CLAIM))
                .thenReturn(UUID.randomUUID().toString());
        when(jwt.getClaimAsString(IdentityJwtClaimValidator.ACTOR_TYPE_CLAIM))
                .thenReturn(IdentityActorType.RETAIL_CUSTOMER.name());
        when(jwt.getClaimAsString(IdentityJwtClaimValidator.TOKEN_USE_CLAIM))
                .thenReturn(IdentityJwtClaimValidator.ACCESS_TOKEN_USE);
        when(jwt.getIssuedAt()).thenReturn(issuedAt);
        when(jwt.getNotBefore()).thenReturn(issuedAt);
        when(jwt.getExpiresAt()).thenReturn(expiresAt);
        return jwt;
    }

    private static Jwt lifecycleToken(Instant issuedAt) {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getHeaders()).thenReturn(Map.of("kid", "retired-key"));
        when(jwt.getIssuedAt()).thenReturn(issuedAt);
        return jwt;
    }
}
