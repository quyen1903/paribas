package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.domain.JwtSigningKey;
import com.quinnbank.core.identity.domain.enums.JwtSigningKeyStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

interface SpringDataJwtSigningKeyRepository extends JpaRepository<JwtSigningKey, String> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select signingKey from JwtSigningKey signingKey where signingKey.status = :status")
    Optional<JwtSigningKey> findByStatusForUpdate(@Param("status") JwtSigningKeyStatus status);
}
