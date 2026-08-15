package com.quinnbank.core.identity.application.service;

import com.quinnbank.core.identity.application.command.RegisterIdentityCommand;
import com.quinnbank.core.identity.application.exception.IdentityAlreadyExistsException;
import com.quinnbank.core.identity.application.exception.InvalidIdentityRegistrationException;
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
public class RegisterIdentityService {
    private static final AuthenticationActor REGISTRATION_SERVICE = AuthenticationActor.of(
            IdentityActorType.SERVICE_ACCOUNT,
            "identity-self-registration"
    );

    private final IdentityAccountRepository identityAccounts;
    private final AuthenticationSessionRepository sessions;
    private final AuthenticationAuditRepository audits;
    private final PasswordService passwords;
    private final RegistrationPasswordPolicy passwordPolicy;
    private final AuthenticationPolicy authenticationPolicy;
    private final AuthenticationThrottle throttle;
    private final TokenPairService tokenPairs;
    private final Clock clock;

    public RegisterIdentityService(
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

    @Transactional(noRollbackFor = IdentityAlreadyExistsException.class)
    public IssuedTokenPair register(RegisterIdentityCommand command) {
        Instant now = AuthenticationTimestampPolicy.jwtCompatible(clock.instant());
        throttle.checkRegistration(command.sourceAddress(), now);
        String loginIdentifier;
        try {
            loginIdentifier = IdentityAccount.normalizeLoginIdentifier(command.loginIdentifier());
            passwordPolicy.validate(command.rawPassword());
        } catch (IllegalArgumentException exception) {
            throw new InvalidIdentityRegistrationException();
        }

        if (identityAccounts.existsByLoginIdentifier(loginIdentifier)) {
            audits.saveAll(List.of(anonymousRegistrationRejection(command.correlationId(), now)));
            throw new IdentityAlreadyExistsException();
        }

        UUID identityId = UUID.randomUUID();
        IdentityAccount identity = IdentityAccount.provision(
            identityId,
            identityId,//this bug need to be fix, we have to pass the ID from KYC instead.
            IdentityActorType.RETAIL_CUSTOMER,
            loginIdentifier,
            passwords.encode(command.rawPassword()),
            REGISTRATION_SERVICE,
            command.correlationId(),
            now
        );
        identity.enable(REGISTRATION_SERVICE, command.correlationId(), now);
        identityAccounts.save(identity);

        AuthenticationSession session = AuthenticationSession.open(
            UUID.randomUUID(),
            identityId,
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

    private static AuthenticationAuditEvent anonymousRegistrationRejection(
            String correlationId,
            Instant now
    ) {
        return AuthenticationAuditEvent.recordAnonymous(
            IdentityActorType.RETAIL_CUSTOMER,
            AuthenticationAction.REGISTRATION_REJECTED,
            AuthenticationDecision.FAILURE,
            AuthenticationMethod.PASSWORD,
            "REGISTRATION_REJECTED",
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
