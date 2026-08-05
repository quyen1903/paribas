package com.quinnbank.core.identity.application.port;

import com.quinnbank.core.identity.domain.IdentityAccount;

import java.util.Optional;
import java.util.UUID;

public interface IdentityAccountRepository {
    boolean existsByLoginIdentifier(String loginIdentifier);

    Optional<IdentityAccount> findByLoginIdentifierForUpdate(String loginIdentifier);

    Optional<IdentityAccount> findById(UUID identityId);

    Optional<IdentityAccount> findByIdForUpdate(UUID identityId);

    IdentityAccount save(IdentityAccount identityAccount);
}
