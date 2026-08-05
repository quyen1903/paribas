package com.quinnbank.core.identity.domain;

import com.quinnbank.core.identity.domain.enums.AuthenticationSessionStatus;
import com.quinnbank.core.identity.domain.enums.RefreshTokenRotationResult;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "authentication_sessions", schema = "identity")
public class AuthenticationSession {
    private static final String REPLAY_REASON_CODE = "REFRESH_TOKEN_REPLAY_DETECTED";

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    @Column(name = "identity_account_id", nullable = false, updatable = false)
    private UUID identityId;

    @Column(name = "current_refresh_token_id", nullable = false)
    private UUID currentRefreshTokenId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private AuthenticationSessionStatus status;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "revocation_reason_code", length = 64)
    private String revocationReasonCode;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected AuthenticationSession() {
    }

    public static AuthenticationSession open(
            UUID sessionId,
            UUID identityId,
            UUID currentRefreshTokenId,
            Instant expiresAt,
            Instant now
    ) {
        Instant requiredNow = requirePresent(now, "now");
        Instant requiredExpiresAt = requirePresent(expiresAt, "expiresAt");
        if (!requiredExpiresAt.isAfter(requiredNow)) {
            throw new IllegalArgumentException("expiresAt must be after now.");
        }

        AuthenticationSession session = new AuthenticationSession();
        session.id = requirePresent(sessionId, "sessionId");
        session.identityId = requirePresent(identityId, "identityId");
        session.currentRefreshTokenId = requirePresent(currentRefreshTokenId, "currentRefreshTokenId");
        session.status = AuthenticationSessionStatus.ACTIVE;
        session.expiresAt = requiredExpiresAt;
        session.createdAt = requiredNow;
        session.updatedAt = requiredNow;
        return session;
    }

    /**
     * Atomically evaluates the presented refresh-token id and rotates it. A
     * stale id is treated as replay and permanently revokes the session.
     */
    public RefreshTokenRotationResult rotateRefreshToken(
            UUID presentedRefreshTokenId,
            UUID replacementRefreshTokenId,
            Instant replacementExpiresAt,
            Instant now
    ) {
        UUID requiredPresentedId = requirePresent(presentedRefreshTokenId, "presentedRefreshTokenId");
        UUID requiredReplacementId = requirePresent(replacementRefreshTokenId, "replacementRefreshTokenId");
        Instant requiredReplacementExpiry = requirePresent(replacementExpiresAt, "replacementExpiresAt");
        requireTransitionTime(now);

        if (requiredReplacementId.equals(requiredPresentedId)
                || !requiredReplacementExpiry.isAfter(now)
                || !isActive(now)) {
            return RefreshTokenRotationResult.INVALID;
        }
        if (!currentRefreshTokenId.equals(requiredPresentedId)) {
            markRevoked(REPLAY_REASON_CODE, now);
            return RefreshTokenRotationResult.REPLAY_DETECTED;
        }

        currentRefreshTokenId = requiredReplacementId;
        expiresAt = requiredReplacementExpiry;
        updatedAt = now;
        return RefreshTokenRotationResult.ROTATED;
    }

    public boolean matchesCurrentRefreshTokenId(UUID presentedRefreshTokenId) {
        return presentedRefreshTokenId != null && currentRefreshTokenId.equals(presentedRefreshTokenId);
    }

    public boolean isActive(Instant now) {
        requirePresent(now, "now");
        return status == AuthenticationSessionStatus.ACTIVE && now.isBefore(expiresAt);
    }

    public void revoke(String reasonCode, Instant now) {
        String requiredReasonCode = requireReasonCode(reasonCode);
        requireTransitionTime(now);
        if (status == AuthenticationSessionStatus.REVOKED) {
            throw new IllegalStateException("Authentication session is already revoked.");
        }
        markRevoked(requiredReasonCode, now);
    }

    public UUID getId() {
        return id;
    }

    public long getVersion() {
        return version;
    }

    public UUID getIdentityId() {
        return identityId;
    }

    public UUID getCurrentRefreshTokenId() {
        return currentRefreshTokenId;
    }

    public AuthenticationSessionStatus getStatus() {
        return status;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public String getRevocationReasonCode() {
        return revocationReasonCode;
    }

    @Override
    public String toString() {
        return "AuthenticationSession[id=redacted, status=" + status + "]";
    }

    private void markRevoked(String reasonCode, Instant now) {
        status = AuthenticationSessionStatus.REVOKED;
        revokedAt = now;
        revocationReasonCode = reasonCode;
        updatedAt = now;
    }

    private void requireTransitionTime(Instant now) {
        requirePresent(now, "now");
        if (now.isBefore(updatedAt)) {
            throw new IllegalArgumentException("Transition time cannot move backwards.");
        }
    }

    private static String requireReasonCode(String value) {
        if (value == null || !value.matches("[A-Z0-9][A-Z0-9_]{0,63}")) {
            throw new IllegalArgumentException("reasonCode has an invalid format.");
        }
        return value;
    }

    private static <T> T requirePresent(T value, String fieldName) {
        if (value == null) {
            throw new IllegalArgumentException(fieldName + " is required.");
        }
        return value;
    }
}
