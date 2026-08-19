package com.quinnbank.core.identity.application.service;

import com.quinnbank.core.identity.application.command.LoginIdentityCommand;
import com.quinnbank.core.identity.application.exception.InvalidCredentialsException;
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
import com.quinnbank.core.identity.domain.AuthenticationActor;
import com.quinnbank.core.identity.domain.AuthenticationAuditEvent;
import com.quinnbank.core.identity.domain.AuthenticationSession;
import com.quinnbank.core.identity.domain.IdentityAccount;
import com.quinnbank.core.identity.domain.enums.AuthenticationAction;
import com.quinnbank.core.identity.domain.enums.AuthenticationDecision;
import com.quinnbank.core.identity.domain.enums.AuthenticationMethod;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class LoginIdentityService {
    private static final String INVALID_LOGIN_BUCKET = "invalid";

    private final IdentityAccountRepository identityAccounts;
    private final AuthenticationSessionRepository sessions;
    private final AuthenticationAuditRepository audits;
    private final PasswordService passwords;
    private final RegistrationPasswordPolicy passwordPolicy;
    private final AuthenticationPolicy authenticationPolicy;
    private final AuthenticationThrottle throttle;
    private final TokenPairService tokenPairs;
    private final Clock clock;

    public LoginIdentityService(
            IdentityAccountRepository identityAccounts,
            AuthenticationSessionRepository sessions,
            AuthenticationAuditRepository audits,
            PasswordService passwords,
            RegistrationPasswordPolicy passwordPolicy,
            AuthenticationPolicy authenticationPolicy,
            AuthenticationThrottle throttle,
            TokenPairService tokenPairs,
            Clock clock
    ) {
        this.identityAccounts = identityAccounts;
        this.sessions = sessions;
        this.audits = audits;
        this.passwords = passwords;
        this.passwordPolicy = passwordPolicy;
        this.authenticationPolicy = authenticationPolicy;
        this.throttle = throttle;
        this.tokenPairs = tokenPairs;
        this.clock = clock;
    }

    @Transactional(noRollbackFor = InvalidCredentialsException.class)
    public IssuedTokenPair login(LoginIdentityCommand command) {
        Instant now = AuthenticationTimestampPolicy.jwtCompatible(clock.instant());
        String loginIdentifier = normalizeForLogin(command, now);
        throttle.checkLogin(command.sourceAddress(), loginIdentifier, now);

        IdentityAccount identity = identityAccounts
            .findByLoginIdentifierForUpdate(loginIdentifier)
            .orElse(null);

        if (identity == null) {
            passwords.performDummyMatch(command.rawPassword());
            audits.saveAll(List.of(anonymousFailure(command.correlationId(), now)));
            throw new InvalidCredentialsException();
        }

        boolean passwordMatches = passwords.matches(
                command.rawPassword(),
                identity.getEncodedPasswordForAuthentication()
        );
        if (!isPasswordTokenActor(identity.getActorType()) || !identity.canAuthenticate(now)) {
            audits.saveAll(List.of(knownFailure(identity, command.correlationId(), now)));
            throw new InvalidCredentialsException();
        }
        if (!passwordMatches) {
            identity.recordAuthenticationFailure(
                    authenticationPolicy.lockThreshold(),
                    authenticationPolicy.lockDuration(),
                    command.correlationId(),
                    now
            );
            identityAccounts.save(identity);
            audits.saveAll(identity.releaseAuditEvents());
            throw new InvalidCredentialsException();
        }

        identity.recordAuthenticationSuccess(command.correlationId(), now);
        identityAccounts.save(identity);
        AuthenticationSession session = AuthenticationSession.open(
            UUID.randomUUID(),
            identity.getId(),
            UUID.randomUUID(),
            now.plus(authenticationPolicy.refreshTokenTtl()),
            now
        );
        sessions.save(session);
        IssuedTokenPair issuedTokens = tokenPairs.issuePair(identity, session, now);

        List<AuthenticationAuditEvent> events = new ArrayList<>(identity.releaseAuditEvents());
        events.add(tokenIssued(identity, command.correlationId(), now));
        audits.saveAll(events);
        return issuedTokens;
    }

    private String normalizeForLogin(LoginIdentityCommand command, Instant now) {
        try {
            String normalized = IdentityAccount.normalizeLoginIdentifier(command.loginIdentifier());
            passwordPolicy.validate(command.rawPassword());
            return normalized;
        } catch (IllegalArgumentException exception) {
            throttle.checkLogin(command.sourceAddress(), INVALID_LOGIN_BUCKET, now);
            passwords.performDummyMatch("invalid-password-input");
            audits.saveAll(List.of(anonymousFailure(command.correlationId(), now)));
            throw new InvalidCredentialsException();
        }
    }

    private static boolean isPasswordTokenActor(IdentityActorType actorType) {
        return actorType == IdentityActorType.RETAIL_CUSTOMER
                || actorType == IdentityActorType.BUSINESS_CUSTOMER;
    }

    private static AuthenticationAuditEvent anonymousFailure(String correlationId, Instant now) {
        return AuthenticationAuditEvent.recordAnonymous(
                IdentityActorType.RETAIL_CUSTOMER,
                AuthenticationAction.AUTHENTICATION_FAILED,
                AuthenticationDecision.FAILURE,
                AuthenticationMethod.PASSWORD,
                "INVALID_CREDENTIALS",
                correlationId,
                now
        );
    }

    private static AuthenticationAuditEvent knownFailure(
            IdentityAccount identity,
            String correlationId,
            Instant now
    ) {
        return AuthenticationAuditEvent.recordForKnownIdentity(
                identity.getId(),
                AuthenticationActor.of(identity.getActorType(), "ANONYMOUS"),
                AuthenticationAction.AUTHENTICATION_FAILED,
                AuthenticationDecision.FAILURE,
                AuthenticationMethod.PASSWORD,
                "INVALID_CREDENTIALS",
                correlationId,
                now
        );
    }

    private static AuthenticationAuditEvent tokenIssued(
            IdentityAccount identity,
            String correlationId,
            Instant now
    ) {
        return AuthenticationAuditEvent.recordForKnownIdentity(
                identity.getId(),
                AuthenticationActor.of(identity.getActorType(), identity.getSubjectId().toString()),
                AuthenticationAction.TOKEN_PAIR_ISSUED,
                AuthenticationDecision.SUCCESS,
                AuthenticationMethod.JWT,
                "TOKEN_PAIR_ISSUED",
                correlationId,
                now
        );
    }
}
