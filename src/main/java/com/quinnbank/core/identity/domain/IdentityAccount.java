package com.quinnbank.core.identity.domain;

import com.quinnbank.core.identity.domain.enums.AuthenticationAction;
import com.quinnbank.core.identity.domain.enums.AuthenticationDecision;
import com.quinnbank.core.identity.domain.enums.AuthenticationMethod;
import com.quinnbank.core.identity.domain.enums.IdentityAccountStatus;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Entity
@Table(
        name = "identity_accounts",
        schema = "identity",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_identity_accounts_actor_subject",
                        columnNames = {"actor_type", "subject_id"}
                )
        }
)
public class IdentityAccount {
    private static final int MAX_LOGIN_IDENTIFIER_LENGTH = 254;
    private static final int MAX_FAILED_ATTEMPTS_THRESHOLD = 1_000;

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    @Column(name = "subject_id", nullable = false, updatable = false)
    private UUID subjectId;

    @Enumerated(EnumType.STRING)
    @Column(name = "actor_type", nullable = false, length = 30, updatable = false)
    private IdentityActorType actorType;

    @Column(name = "login_identifier", nullable = false, length = MAX_LOGIN_IDENTIFIER_LENGTH)
    private String loginIdentifier;

    @Column(name = "encoded_password", nullable = false, length = 500)
    private String encodedPassword;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private IdentityAccountStatus status;

    @Column(name = "failed_authentication_attempts", nullable = false)
    private int failedAuthenticationAttempts;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "credentials_changed_at", nullable = false)
    private Instant credentialsChangedAt;

    @Column(name = "last_authenticated_at")
    private Instant lastAuthenticatedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Transient
    private List<AuthenticationAuditEvent> pendingAuditEvents = new ArrayList<>();

    protected IdentityAccount() {
    }

    public static IdentityAccount provision(
        UUID id,
        UUID subjectId,
        IdentityActorType actorType,
        String loginIdentifier,
        EncodedPassword encodedPassword,
        AuthenticationActor provisioningActor,
        String correlationId,
        Instant now
    ) {
        IdentityAccount account = new IdentityAccount();
        account.id = requirePresent(id, "id");
        account.subjectId = requirePresent(subjectId, "subjectId");
        account.actorType = requirePresent(actorType, "actorType");
        requirePasswordActorType(actorType);
        account.loginIdentifier = normalizeLoginIdentifier(loginIdentifier);
        account.encodedPassword = requirePresent(encodedPassword, "encodedPassword").value();
        account.status = IdentityAccountStatus.DISABLED;
        account.credentialsChangedAt = requirePresent(now, "now");
        account.createdAt = now;
        account.updatedAt = now;
        requirePresent(provisioningActor, "provisioningActor");
        requireCorrelationId(correlationId);
        account.recordAudit(
            provisioningActor,
            AuthenticationAction.ACCOUNT_PROVISIONED,
            AuthenticationDecision.SUCCESS,
            null,
            "ACCOUNT_PROVISIONED",
            correlationId,
            now
        );
        return account;
    }

    public boolean canAuthenticate(Instant now) {
        requirePresent(now, "now");
        return status == IdentityAccountStatus.ACTIVE
                && (lockedUntil == null || !now.isBefore(lockedUntil));
    }

    public void recordAuthenticationFailure(
            int lockThreshold,
            Duration lockDuration,
            String correlationId,
            Instant now
    ) {
        validateLockPolicy(lockThreshold, lockDuration);
        requireCorrelationId(correlationId);
        requireTransitionTime(now);
        requireActive();
        clearExpiredLock(now);
        requireNotTemporarilyLocked(now);
        Instant lockExpiry = now.plus(lockDuration);

        failedAuthenticationAttempts++;
        AuthenticationAction action = AuthenticationAction.AUTHENTICATION_FAILED;
        String reasonCode = "INVALID_CREDENTIALS";
        if (failedAuthenticationAttempts >= lockThreshold) {
            failedAuthenticationAttempts = lockThreshold;
            lockedUntil = lockExpiry;
            action = AuthenticationAction.ACCOUNT_TEMPORARILY_LOCKED;
            reasonCode = "FAILURE_THRESHOLD_REACHED";
        }

        updatedAt = now;
        recordAudit(
            unauthenticatedActor(),
            action,
            AuthenticationDecision.FAILURE,
            AuthenticationMethod.PASSWORD,
            reasonCode,
            correlationId,
            now
        );
    }

    public void recordAuthenticationSuccess(String correlationId, Instant now) {
        requireCorrelationId(correlationId);
        requireTransitionTime(now);
        requireActive();
        clearExpiredLock(now);
        requireNotTemporarilyLocked(now);

        failedAuthenticationAttempts = 0;
        lockedUntil = null;
        lastAuthenticatedAt = now;
        updatedAt = now;
        recordAudit(
            selfActor(),
            AuthenticationAction.AUTHENTICATION_SUCCEEDED,
            AuthenticationDecision.SUCCESS,
            AuthenticationMethod.PASSWORD,
            "CREDENTIALS_ACCEPTED",
            correlationId,
            now
        );
    }

    public void changePassword(
        EncodedPassword newEncodedPassword,
        AuthenticationActor actor,
        String correlationId,
        Instant now
    ) {
        AuthenticationActor requiredActor = requirePresent(actor, "actor");
        requireCorrelationId(correlationId);
        requireNotClosed();
        requireTransitionTime(now);
        String newValue = requirePresent(newEncodedPassword, "newEncodedPassword").value();
        if (newValue.equals(encodedPassword)) {
            throw new IllegalArgumentException("New encoded password must differ from the current value.");
        }

        encodedPassword = newValue;
        credentialsChangedAt = now;
        failedAuthenticationAttempts = 0;
        lockedUntil = null;
        updatedAt = now;
        recordAudit(
            requiredActor,
            AuthenticationAction.PASSWORD_CHANGED,
            AuthenticationDecision.SUCCESS,
            AuthenticationMethod.PASSWORD,
            "PASSWORD_CHANGED",
            correlationId,
            now
        );
    }

    public void enable(
        AuthenticationActor actor,
        String correlationId,
        Instant now
    ) {
        AuthenticationActor requiredActor = requirePresent(actor, "actor");
        requireCorrelationId(correlationId);
        requireTransitionTime(now);
        if (status != IdentityAccountStatus.DISABLED) {
            throw new IllegalStateException("Only disabled identity accounts can be enabled.");
        }

        status = IdentityAccountStatus.ACTIVE;
        failedAuthenticationAttempts = 0;
        lockedUntil = null;
        updatedAt = now;
        recordAudit(
            requiredActor,
            AuthenticationAction.ACCOUNT_ENABLED,
            AuthenticationDecision.SUCCESS,
            null,
            "ACCOUNT_ENABLED",
            correlationId,
            now
        );
    }

    public void disable(
            AuthenticationActor actor,
            String reasonCode,
            String correlationId,
            Instant now
    ) {
        AuthenticationActor requiredActor = requirePresent(actor, "actor");
        String requiredReasonCode = requireReasonCode(reasonCode);
        requireCorrelationId(correlationId);
        requireNotClosed();
        requireTransitionTime(now);
        if (status == IdentityAccountStatus.DISABLED) {
            throw new IllegalStateException("Identity account is already disabled.");
        }

        status = IdentityAccountStatus.DISABLED;
        failedAuthenticationAttempts = 0;
        lockedUntil = null;
        updatedAt = now;
        recordAudit(
            requiredActor,
            AuthenticationAction.ACCOUNT_DISABLED,
            AuthenticationDecision.SUCCESS,
            null,
            requiredReasonCode,
            correlationId,
            now
        );
    }

    public void close(
        AuthenticationActor actor,
        String reasonCode,
        String correlationId,
        Instant now
    ) {
        AuthenticationActor requiredActor = requirePresent(actor, "actor");
        String requiredReasonCode = requireReasonCode(reasonCode);
        requireCorrelationId(correlationId);
        requireTransitionTime(now);
        if (status == IdentityAccountStatus.CLOSED) {
            throw new IllegalStateException("Identity account is already closed.");
        }

        status = IdentityAccountStatus.CLOSED;
        failedAuthenticationAttempts = 0;
        lockedUntil = null;
        updatedAt = now;
        recordAudit(
            requiredActor,
            AuthenticationAction.ACCOUNT_CLOSED,
            AuthenticationDecision.SUCCESS,
            null,
            requiredReasonCode,
            correlationId,
            now
        );
    }

    public List<AuthenticationAuditEvent> releaseAuditEvents() {
        List<AuthenticationAuditEvent> events = List.copyOf(pendingAuditEvents);
        pendingAuditEvents.clear();
        return events;
    }

    public UUID getId() {
        return id;
    }

    public long getVersion() {
        return version;
    }

    public UUID getSubjectId() {
        return subjectId;
    }

    public IdentityActorType getActorType() {
        return actorType;
    }

    public String getLoginIdentifier() {
        return loginIdentifier;
    }

    /**
     * Internal authentication material. Callers must never log, serialize, or
     * expose this value through an API.
     */
    public String getEncodedPasswordForAuthentication() {
        return encodedPassword;
    }

    public IdentityAccountStatus getStatus() {
        return status;
    }

    public int getFailedAuthenticationAttempts() {
        return failedAuthenticationAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public Instant getCredentialsChangedAt() {
        return credentialsChangedAt;
    }

    public Instant getLastAuthenticatedAt() {
        return lastAuthenticatedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    @Override
    public String toString() {
        return "IdentityAccount[id=" + id + ", actorType=" + actorType + ", status=" + status + "]";
    }

    private void recordAudit(
        AuthenticationActor actor,
        AuthenticationAction action,
        AuthenticationDecision decision,
        AuthenticationMethod authenticationMethod,
        String reasonCode,
        String correlationId,
        Instant occurredAt
    ) {
        pendingAuditEvents.add(AuthenticationAuditEvent.record(
            id,
            actor,
            action,
            decision,
            authenticationMethod,
            reasonCode,
            correlationId,
            occurredAt
        ));
    }

    private AuthenticationActor selfActor() {
        return AuthenticationActor.of(actorType, subjectId.toString());
    }

    private AuthenticationActor unauthenticatedActor() {
        return AuthenticationActor.of(actorType, "ANONYMOUS");
    }

    private void clearExpiredLock(Instant now) {
        if (lockedUntil != null && !now.isBefore(lockedUntil)) {
            lockedUntil = null;
            failedAuthenticationAttempts = 0;
        }
    }

    private void requireNotTemporarilyLocked(Instant now) {
        if (lockedUntil != null && now.isBefore(lockedUntil)) {
            throw new IllegalStateException("Identity account is temporarily locked.");
        }
    }

    private void requireActive() {
        if (status != IdentityAccountStatus.ACTIVE) {
            throw new IllegalStateException("Identity account is not active.");
        }
    }

    private void requireNotClosed() {
        if (status == IdentityAccountStatus.CLOSED) {
            throw new IllegalStateException("Closed identity accounts cannot be changed.");
        }
    }

    private void requireTransitionTime(Instant now) {
        requirePresent(now, "now");
        if (now.isBefore(updatedAt)) {
            throw new IllegalArgumentException("Transition time cannot move backwards.");
        }
    }

    private static void validateLockPolicy(int threshold, Duration duration) {
        if (threshold < 1 || threshold > MAX_FAILED_ATTEMPTS_THRESHOLD) {
            throw new IllegalArgumentException("lockThreshold is invalid.");
        }
        if (duration == null || duration.isZero() || duration.isNegative()) {
            throw new IllegalArgumentException("lockDuration must be positive.");
        }
    }

    private static void requirePasswordActorType(IdentityActorType actorType) {
        if (actorType == IdentityActorType.SERVICE_ACCOUNT
                || actorType == IdentityActorType.THIRD_PARTY_PARTNER
                || actorType == IdentityActorType.BATCH_JOB) {
            throw new IllegalArgumentException(
                    "This identity type requires a non-password authentication design."
            );
        }
    }

    public static String normalizeLoginIdentifier(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("loginIdentifier is required.");
        }

        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (normalized.length() > MAX_LOGIN_IDENTIFIER_LENGTH) {
            throw new IllegalArgumentException("loginIdentifier is too long.");
        }
        if (normalized.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("loginIdentifier contains invalid characters.");
        }
        return normalized;
    }

    private static String requireReasonCode(String value) {
        if (value == null || !value.matches("[A-Z0-9][A-Z0-9_]{0,63}")) {
            throw new IllegalArgumentException("reasonCode has an invalid format.");
        }
        return value;
    }

    private static void requireCorrelationId(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("correlationId is required.");
        }
        String trimmed = value.trim();
        if (trimmed.length() > 100 || trimmed.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("correlationId is invalid.");
        }
    }

    private static <T> T requirePresent(T value, String fieldName) {
        if (value == null) {
            throw new IllegalArgumentException(fieldName + " is required.");
        }
        return value;
    }
}
