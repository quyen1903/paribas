package com.quinnbank.core.identity.application.port;

import com.quinnbank.core.identity.domain.IdentityAccount;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;

import java.util.Optional;
import java.util.UUID;

public interface IdentityAccountRepository {
    boolean existsByLoginIdentifier(String loginIdentifier);

    Optional<IdentityAccount> findByLoginIdentifierForUpdate(String loginIdentifier);

    Optional<IdentityAccount> findById(UUID identityId);

    Optional<IdentityAccount> findByIdForUpdate(UUID identityId);

    Optional<IdentityAccount> findByActorTypeAndSubjectIdForUpdate(
        IdentityActorType actorType,
        UUID subjectId
    );

    IdentityAccount save(IdentityAccount identityAccount);
}
