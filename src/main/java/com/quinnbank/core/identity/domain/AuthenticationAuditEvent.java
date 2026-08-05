package com.quinnbank.core.identity.domain;

import com.quinnbank.core.identity.domain.enums.AuthenticationAction;
import com.quinnbank.core.identity.domain.enums.AuthenticationDecision;
import com.quinnbank.core.identity.domain.enums.AuthenticationMethod;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "authentication_audit_events", schema = "identity")
public class AuthenticationAuditEvent {
    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "target_identity_id", updatable = false)
    private UUID targetIdentityId;

    @Enumerated(EnumType.STRING)
    @Column(name = "actor_type", nullable = false, length = 30, updatable = false)
    private IdentityActorType actorType;

    @Column(name = "actor_id", nullable = false, length = 100, updatable = false)
    private String actorId;

    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false, length = 50, updatable = false)
    private AuthenticationAction action;

    @Enumerated(EnumType.STRING)
    @Column(name = "decision", nullable = false, length = 20, updatable = false)
    private AuthenticationDecision decision;

    @Enumerated(EnumType.STRING)
    @Column(name = "authentication_method", length = 30, updatable = false)
    private AuthenticationMethod authenticationMethod;

    @Column(name = "reason_code", nullable = false, length = 64, updatable = false)
    private String reasonCode;

    @Column(name = "correlation_id", nullable = false, length = 100, updatable = false)
    private String correlationId;

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt;

    protected AuthenticationAuditEvent() {
    }

    static AuthenticationAuditEvent record(
            UUID targetIdentityId,
            AuthenticationActor actor,
            AuthenticationAction action,
            AuthenticationDecision decision,
            AuthenticationMethod authenticationMethod,
            String reasonCode,
            String correlationId,
            Instant occurredAt
    ) {
        return recordForKnownIdentity(
                targetIdentityId,
                actor,
                action,
                decision,
                authenticationMethod,
                reasonCode,
                correlationId,
                occurredAt
        );
    }

    public static AuthenticationAuditEvent recordForKnownIdentity(
            UUID targetIdentityId,
            AuthenticationActor actor,
            AuthenticationAction action,
            AuthenticationDecision decision,
            AuthenticationMethod authenticationMethod,
            String reasonCode,
            String correlationId,
            Instant occurredAt
    ) {
        UUID requiredTargetIdentityId = requirePresent(targetIdentityId, "targetIdentityId");
        AuthenticationActor requiredActor = requirePresent(actor, "actor");
        return create(
                requiredTargetIdentityId,
                requiredActor.type(),
                requiredActor.id(),
                action,
                decision,
                authenticationMethod,
                reasonCode,
                correlationId,
                occurredAt
        );
    }

    /**
     * Records a public-flow rejection without retaining an untrusted submitted
     * login identifier. Anonymous records use a fixed actor id.
     */
    public static AuthenticationAuditEvent recordAnonymous(
            IdentityActorType actorType,
            AuthenticationAction action,
            AuthenticationDecision decision,
            AuthenticationMethod authenticationMethod,
            String reasonCode,
            String correlationId,
            Instant occurredAt
    ) {
        AuthenticationAction requiredAction = requirePresent(action, "action");
        if (!allowsAnonymousTarget(requiredAction)) {
            throw new IllegalArgumentException("action requires a known target identity.");
        }
        return create(
                null,
                requirePresent(actorType, "actorType"),
                "ANONYMOUS",
                requiredAction,
                decision,
                authenticationMethod,
                reasonCode,
                correlationId,
                occurredAt
        );
    }

    private static AuthenticationAuditEvent create(
            UUID targetIdentityId,
            IdentityActorType actorType,
            String actorId,
            AuthenticationAction action,
            AuthenticationDecision decision,
            AuthenticationMethod authenticationMethod,
            String reasonCode,
            String correlationId,
            Instant occurredAt
    ) {
        AuthenticationAuditEvent event = new AuthenticationAuditEvent();
        event.id = UUID.randomUUID();
        event.targetIdentityId = targetIdentityId;
        event.actorType = requirePresent(actorType, "actorType");
        event.actorId = requireText(actorId, "actorId", 100);
        event.action = requirePresent(action, "action");
        event.decision = requirePresent(decision, "decision");
        event.authenticationMethod = authenticationMethod;
        event.reasonCode = requireCode(reasonCode, "reasonCode", 64);
        event.correlationId = requireText(correlationId, "correlationId", 100);
        event.occurredAt = requirePresent(occurredAt, "occurredAt");
        return event;
    }

    private static boolean allowsAnonymousTarget(AuthenticationAction action) {
        return action == AuthenticationAction.REGISTRATION_REJECTED
                || action == AuthenticationAction.AUTHENTICATION_FAILED
                || action == AuthenticationAction.TOKEN_REFRESH_REJECTED;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTargetIdentityId() {
        return targetIdentityId;
    }

    public IdentityActorType getActorType() {
        return actorType;
    }

    public String getActorId() {
        return actorId;
    }

    public AuthenticationAction getAction() {
        return action;
    }

    public AuthenticationDecision getDecision() {
        return decision;
    }

    public AuthenticationMethod getAuthenticationMethod() {
        return authenticationMethod;
    }

    public String getReasonCode() {
        return reasonCode;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    @Override
    public String toString() {
        return "AuthenticationAuditEvent[id=" + id + ", action=" + action + ", decision=" + decision + "]";
    }

    private static String requireCode(String value, String fieldName, int maxLength) {
        String code = requireText(value, fieldName, maxLength);
        if (!code.matches("[A-Z0-9][A-Z0-9_]*")) {
            throw new IllegalArgumentException(fieldName + " has an invalid format.");
        }
        return code;
    }

    private static String requireText(String value, String fieldName, int maxLength) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " is required.");
        }
        String trimmed = value.trim();
        if (trimmed.length() > maxLength) {
            throw new IllegalArgumentException(fieldName + " is too long.");
        }
        if (trimmed.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(fieldName + " contains invalid characters.");
        }
        return trimmed;
    }

    private static <T> T requirePresent(T value, String fieldName) {
        if (value == null) {
            throw new IllegalArgumentException(fieldName + " is required.");
        }
        return value;
    }
}
