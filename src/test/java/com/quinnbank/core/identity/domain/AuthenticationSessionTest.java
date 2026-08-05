package com.quinnbank.core.identity.domain;

import com.quinnbank.core.identity.domain.enums.AuthenticationSessionStatus;
import com.quinnbank.core.identity.domain.enums.RefreshTokenRotationResult;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthenticationSessionTest {
    private static final UUID SESSION_ID = UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final UUID IDENTITY_ID = UUID.fromString("20000000-0000-0000-0000-000000000001");
    private static final UUID FIRST_TOKEN_ID = UUID.fromString("30000000-0000-0000-0000-000000000001");
    private static final UUID SECOND_TOKEN_ID = UUID.fromString("30000000-0000-0000-0000-000000000002");
    private static final UUID THIRD_TOKEN_ID = UUID.fromString("30000000-0000-0000-0000-000000000003");
    private static final Instant CREATED_AT = Instant.parse("2026-08-04T00:00:00Z");
    private static final Instant INITIAL_EXPIRY = CREATED_AT.plusSeconds(3_600);

    @Test
    void openCreatesAnActiveBoundedSessionWithoutExposingTokenIdInToString() {
        AuthenticationSession session = openSession();

        assertAll(
                () -> assertEquals(SESSION_ID, session.getId()),
                () -> assertEquals(IDENTITY_ID, session.getIdentityId()),
                () -> assertEquals(FIRST_TOKEN_ID, session.getCurrentRefreshTokenId()),
                () -> assertEquals(AuthenticationSessionStatus.ACTIVE, session.getStatus()),
                () -> assertEquals(INITIAL_EXPIRY, session.getExpiresAt()),
                () -> assertEquals(CREATED_AT, session.getCreatedAt()),
                () -> assertEquals(CREATED_AT, session.getUpdatedAt()),
                () -> assertNull(session.getRevokedAt()),
                () -> assertNull(session.getRevocationReasonCode()),
                () -> assertTrue(session.isActive(CREATED_AT)),
                () -> assertFalse(session.toString().contains(SESSION_ID.toString())),
                () -> assertFalse(session.toString().contains(FIRST_TOKEN_ID.toString())),
                () -> assertFalse(session.toString().contains(IDENTITY_ID.toString()))
        );
    }

    @Test
    void matchingRefreshTokenRotatesExactlyOnce() {
        AuthenticationSession session = openSession();
        Instant rotatedAt = CREATED_AT.plusSeconds(60);
        Instant replacementExpiry = INITIAL_EXPIRY.plusSeconds(600);

        RefreshTokenRotationResult result = session.rotateRefreshToken(
                FIRST_TOKEN_ID,
                SECOND_TOKEN_ID,
                replacementExpiry,
                rotatedAt
        );

        assertAll(
                () -> assertEquals(RefreshTokenRotationResult.ROTATED, result),
                () -> assertEquals(SECOND_TOKEN_ID, session.getCurrentRefreshTokenId()),
                () -> assertEquals(replacementExpiry, session.getExpiresAt()),
                () -> assertEquals(rotatedAt, session.getUpdatedAt()),
                () -> assertTrue(session.matchesCurrentRefreshTokenId(SECOND_TOKEN_ID)),
                () -> assertFalse(session.matchesCurrentRefreshTokenId(FIRST_TOKEN_ID)),
                () -> assertEquals(AuthenticationSessionStatus.ACTIVE, session.getStatus())
        );
    }

    @Test
    void staleRefreshTokenIsReplayAndRevokesTheSession() {
        AuthenticationSession session = openSession();
        Instant firstRotation = CREATED_AT.plusSeconds(60);
        session.rotateRefreshToken(
                FIRST_TOKEN_ID,
                SECOND_TOKEN_ID,
                INITIAL_EXPIRY.plusSeconds(600),
                firstRotation
        );
        Instant replayAt = firstRotation.plusSeconds(1);

        RefreshTokenRotationResult result = session.rotateRefreshToken(
                FIRST_TOKEN_ID,
                THIRD_TOKEN_ID,
                INITIAL_EXPIRY.plusSeconds(1_200),
                replayAt
        );

        assertAll(
                () -> assertEquals(RefreshTokenRotationResult.REPLAY_DETECTED, result),
                () -> assertEquals(AuthenticationSessionStatus.REVOKED, session.getStatus()),
                () -> assertEquals(replayAt, session.getRevokedAt()),
                () -> assertEquals("REFRESH_TOKEN_REPLAY_DETECTED", session.getRevocationReasonCode()),
                () -> assertFalse(session.isActive(replayAt)),
                () -> assertEquals(SECOND_TOKEN_ID, session.getCurrentRefreshTokenId())
        );
    }

    @Test
    void expiredOrNonRotatingReplacementIsInvalidWithoutMutation() {
        AuthenticationSession expiredSession = openSession();
        RefreshTokenRotationResult expiredResult = expiredSession.rotateRefreshToken(
                FIRST_TOKEN_ID,
                SECOND_TOKEN_ID,
                INITIAL_EXPIRY.plusSeconds(60),
                INITIAL_EXPIRY
        );
        AuthenticationSession duplicateIdSession = openSession();
        Instant rotationTime = CREATED_AT.plusSeconds(60);
        RefreshTokenRotationResult duplicateIdResult = duplicateIdSession.rotateRefreshToken(
                FIRST_TOKEN_ID,
                FIRST_TOKEN_ID,
                INITIAL_EXPIRY.plusSeconds(60),
                rotationTime
        );

        assertAll(
                () -> assertEquals(RefreshTokenRotationResult.INVALID, expiredResult),
                () -> assertEquals(FIRST_TOKEN_ID, expiredSession.getCurrentRefreshTokenId()),
                () -> assertEquals(CREATED_AT, expiredSession.getUpdatedAt()),
                () -> assertEquals(RefreshTokenRotationResult.INVALID, duplicateIdResult),
                () -> assertEquals(FIRST_TOKEN_ID, duplicateIdSession.getCurrentRefreshTokenId()),
                () -> assertEquals(CREATED_AT, duplicateIdSession.getUpdatedAt())
        );
    }

    @Test
    void explicitRevocationRequiresAStableReasonAndIsIrreversible() {
        AuthenticationSession session = openSession();
        Instant revokedAt = CREATED_AT.plusSeconds(60);

        session.revoke("USER_LOGOUT", revokedAt);

        assertAll(
                () -> assertEquals(AuthenticationSessionStatus.REVOKED, session.getStatus()),
                () -> assertEquals("USER_LOGOUT", session.getRevocationReasonCode()),
                () -> assertEquals(revokedAt, session.getRevokedAt()),
                () -> assertFalse(session.isActive(revokedAt)),
                () -> assertThrows(
                        IllegalStateException.class,
                        () -> session.revoke("USER_LOGOUT", revokedAt.plusSeconds(1))
                )
        );
    }

    @Test
    void invalidTimesAndExpiryAreRejectedWithoutPartialMutation() {
        assertThrows(
                IllegalArgumentException.class,
                () -> AuthenticationSession.open(
                        SESSION_ID,
                        IDENTITY_ID,
                        FIRST_TOKEN_ID,
                        CREATED_AT,
                        CREATED_AT
                )
        );

        AuthenticationSession session = openSession();
        assertThrows(
                IllegalArgumentException.class,
                () -> session.rotateRefreshToken(
                        FIRST_TOKEN_ID,
                        SECOND_TOKEN_ID,
                        INITIAL_EXPIRY.plusSeconds(60),
                        CREATED_AT.minusSeconds(1)
                )
        );
        assertAll(
                () -> assertEquals(FIRST_TOKEN_ID, session.getCurrentRefreshTokenId()),
                () -> assertEquals(AuthenticationSessionStatus.ACTIVE, session.getStatus()),
                () -> assertEquals(CREATED_AT, session.getUpdatedAt())
        );
    }

    private static AuthenticationSession openSession() {
        return AuthenticationSession.open(
                SESSION_ID,
                IDENTITY_ID,
                FIRST_TOKEN_ID,
                INITIAL_EXPIRY,
                CREATED_AT
        );
    }
}
