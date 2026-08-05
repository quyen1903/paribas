package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.domain.AuthenticationSession;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

interface SpringDataAuthenticationSessionRepository extends JpaRepository<AuthenticationSession, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select session from AuthenticationSession session where session.id = :sessionId")
    Optional<AuthenticationSession> findByIdForUpdate(@Param("sessionId") UUID sessionId);
}
