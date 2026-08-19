package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.domain.IdentityAccount;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

interface SpringDataIdentityAccountRepository extends JpaRepository<IdentityAccount, UUID> {
    boolean existsByLoginIdentifier(String loginIdentifier);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select identity from IdentityAccount identity where identity.loginIdentifier = :loginIdentifier")
    Optional<IdentityAccount> findByLoginIdentifierForUpdate(
            @Param("loginIdentifier") String loginIdentifier
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select identity from IdentityAccount identity where identity.id = :identityId")
    Optional<IdentityAccount> findByIdForUpdate(@Param("identityId") UUID identityId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
        select identity from IdentityAccount identity
        where identity.actorType = :actorType and identity.subjectId = :subjectId
        """)
    Optional<IdentityAccount> findByActorTypeAndSubjectIdForUpdate(
        @Param("actorType") IdentityActorType actorType,
        @Param("subjectId") UUID subjectId
    );
}
