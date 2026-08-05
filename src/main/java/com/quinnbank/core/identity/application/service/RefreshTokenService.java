package com.quinnbank.core.identity.application.service;

import com.quinnbank.core.identity.application.command.RefreshTokenCommand;
import com.quinnbank.core.identity.application.exception.InvalidRefreshTokenException;
import com.quinnbank.core.identity.application.policy.AuthenticationTimestampPolicy;
import com.quinnbank.core.identity.application.port.AuthenticationAuditRepository;
import com.quinnbank.core.identity.application.port.AuthenticationSessionRepository;
import com.quinnbank.core.identity.application.port.AuthenticationThrottle;
import com.quinnbank.core.identity.application.port.IdentityAccountRepository;
import com.quinnbank.core.identity.application.port.TokenPairService;
import com.quinnbank.core.identity.application.result.IssuedTokenPair;
import com.quinnbank.core.identity.application.result.VerifiedRefreshToken;
import com.quinnbank.core.identity.domain.AuthenticationActor;
import com.quinnbank.core.identity.domain.AuthenticationAuditEvent;
import com.quinnbank.core.identity.domain.AuthenticationSession;
import com.quinnbank.core.identity.domain.IdentityAccount;
import com.quinnbank.core.identity.domain.enums.AuthenticationAction;
import com.quinnbank.core.identity.domain.enums.AuthenticationDecision;
import com.quinnbank.core.identity.domain.enums.AuthenticationMethod;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import com.quinnbank.core.identity.domain.enums.RefreshTokenRotationResult;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class RefreshTokenService {
    private final IdentityAccountRepository identityAccounts;
    private final AuthenticationSessionRepository sessions;
    private final AuthenticationAuditRepository audits;
    private final AuthenticationThrottle throttle;
    private final TokenPairService tokenPairs;
    private final Clock clock;

    public RefreshTokenService(
            IdentityAccountRepository identityAccounts,
            AuthenticationSessionRepository sessions,
            AuthenticationAuditRepository audits,
            AuthenticationThrottle throttle,
            TokenPairService tokenPairs,
            Clock clock
    ) {
        this.identityAccounts = identityAccounts;
        this.sessions = sessions;
        this.audits = audits;
        this.throttle = throttle;
        this.tokenPairs = tokenPairs;
        this.clock = clock;
    }

    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public IssuedTokenPair refresh(RefreshTokenCommand command) {
        Instant now = AuthenticationTimestampPolicy.jwtCompatible(clock.instant());
        throttle.checkRefresh(command.sourceAddress(), now);
        VerifiedRefreshToken verified = verify(command, now);

        AuthenticationSession session = sessions.findByIdForUpdate(verified.sessionId()).orElse(null);
        if (session == null) {
            rejectAnonymous(command.correlationId(), now);
        }
        IdentityAccount identity = identityAccounts.findByIdForUpdate(verified.identityId()).orElse(null);
        if (identity == null) {
            rejectAnonymous(command.correlationId(), now);
        }

        if (!session.getIdentityId().equals(identity.getId())
                || identity.getActorType() != verified.actorType()
                || !verified.expiresAt().equals(
                        AuthenticationTimestampPolicy.jwtCompatible(session.getExpiresAt())
                )
                || verified.issuedAt().isBefore(
                        AuthenticationTimestampPolicy.jwtCompatible(session.getCreatedAt())
                )
                || verified.issuedAt().isBefore(identity.getCredentialsChangedAt())
                || !identity.canAuthenticate(now)) {
            revokeIfActive(session, "IDENTITY_NOT_ACTIVE", now);
            sessions.save(session);
            audits.saveAll(List.of(knownRefreshRejection(identity, command.correlationId(), now)));
            throw new InvalidRefreshTokenException();
        }

        RefreshTokenRotationResult rotation = session.rotateRefreshToken(
                verified.tokenId(),
                UUID.randomUUID(),
                session.getExpiresAt(),
                now
        );
        if (rotation == RefreshTokenRotationResult.REPLAY_DETECTED) {
            sessions.save(session);
            audits.saveAll(replayEvents(identity, command.correlationId(), now));
            throw new InvalidRefreshTokenException();
        }
        if (rotation != RefreshTokenRotationResult.ROTATED) {
            audits.saveAll(List.of(knownRefreshRejection(identity, command.correlationId(), now)));
            throw new InvalidRefreshTokenException();
        }

        sessions.save(session);
        IssuedTokenPair issuedTokens = tokenPairs.issuePair(identity, session, now);
        audits.saveAll(List.of(knownEvent(
                identity,
                AuthenticationAction.TOKEN_REFRESHED,
                AuthenticationDecision.SUCCESS,
                "TOKEN_REFRESHED",
                command.correlationId(),
                now
        )));
        return issuedTokens;
    }

    private VerifiedRefreshToken verify(RefreshTokenCommand command, Instant now) {
        try {
            return tokenPairs.verifyRefreshToken(command.refreshToken());
        } catch (InvalidRefreshTokenException exception) {
            audits.saveAll(List.of(AuthenticationAuditEvent.recordAnonymous(
                    IdentityActorType.RETAIL_CUSTOMER,
                    AuthenticationAction.TOKEN_REFRESH_REJECTED,
                    AuthenticationDecision.FAILURE,
                    AuthenticationMethod.JWT,
                    "INVALID_REFRESH_TOKEN",
                    command.correlationId(),
                    now
            )));
            throw exception;
        }
    }

    private void rejectAnonymous(String correlationId, Instant now) {
        audits.saveAll(List.of(AuthenticationAuditEvent.recordAnonymous(
                IdentityActorType.RETAIL_CUSTOMER,
                AuthenticationAction.TOKEN_REFRESH_REJECTED,
                AuthenticationDecision.FAILURE,
                AuthenticationMethod.JWT,
                "INVALID_REFRESH_TOKEN",
                correlationId,
                now
        )));
        throw new InvalidRefreshTokenException();
    }

    private static void revokeIfActive(AuthenticationSession session, String reasonCode, Instant now) {
        if (session.isActive(now)) {
            session.revoke(reasonCode, now);
        }
    }

    private static List<AuthenticationAuditEvent> replayEvents(
            IdentityAccount identity,
            String correlationId,
            Instant now
    ) {
        List<AuthenticationAuditEvent> events = new ArrayList<>();
        events.add(knownEvent(
                identity,
                AuthenticationAction.REFRESH_TOKEN_REPLAY_DETECTED,
                AuthenticationDecision.FAILURE,
                "REFRESH_TOKEN_REPLAY_DETECTED",
                correlationId,
                now,
                false
        ));
        events.add(knownEvent(
                identity,
                AuthenticationAction.SESSION_REVOKED,
                AuthenticationDecision.SUCCESS,
                "REFRESH_TOKEN_REPLAY_DETECTED",
                correlationId,
                now,
                false
        ));
        return events;
    }

    private static AuthenticationAuditEvent knownRefreshRejection(
            IdentityAccount identity,
            String correlationId,
            Instant now
    ) {
        return knownEvent(
                identity,
                AuthenticationAction.TOKEN_REFRESH_REJECTED,
                AuthenticationDecision.FAILURE,
                "INVALID_REFRESH_TOKEN",
                correlationId,
                now,
                false
        );
    }

    private static AuthenticationAuditEvent knownEvent(
            IdentityAccount identity,
            AuthenticationAction action,
            AuthenticationDecision decision,
            String reasonCode,
            String correlationId,
            Instant now
    ) {
        return knownEvent(identity, action, decision, reasonCode, correlationId, now, true);
    }

    private static AuthenticationAuditEvent knownEvent(
            IdentityAccount identity,
            AuthenticationAction action,
            AuthenticationDecision decision,
            String reasonCode,
            String correlationId,
            Instant now,
            boolean authenticatedActor
    ) {
        return AuthenticationAuditEvent.recordForKnownIdentity(
                identity.getId(),
                AuthenticationActor.of(
                        identity.getActorType(),
                        authenticatedActor ? identity.getSubjectId().toString() : "ANONYMOUS"
                ),
                action,
                decision,
                AuthenticationMethod.JWT,
                reasonCode,
                correlationId,
                now
        );
    }
}
