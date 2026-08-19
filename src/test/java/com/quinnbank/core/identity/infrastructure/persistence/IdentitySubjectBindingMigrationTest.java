package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.application.port.IdentityAccountRepository;
import com.quinnbank.core.identity.domain.AuthenticationActor;
import com.quinnbank.core.identity.domain.EncodedPassword;
import com.quinnbank.core.identity.domain.IdentityAccount;
import com.quinnbank.core.identity.domain.enums.IdentityAccountStatus;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@Transactional
class IdentitySubjectBindingMigrationTest {
    private static final String ENCODED_PASSWORD = "$2b$12$" + "c".repeat(53);

    @Autowired
    private IdentityAccountRepository identities;

    @Autowired
    private EntityManager entityManager;

    @Test
    void databaseTriggerRejectsAChangedCustomerSubjectBinding() {
        IdentityAccount identity = persistDisabledIdentity();

        assertThrows(
            PersistenceException.class,
            () -> entityManager.createNativeQuery("""
                    UPDATE identity.identity_accounts
                    SET subject_id = :replacementSubjectId
                    WHERE id = :identityId
                    """)
                .setParameter("replacementSubjectId", UUID.randomUUID())
                .setParameter("identityId", identity.getId())
                .executeUpdate()
        );
    }

    @Test
    void databaseTriggerAllowsAnIdentityLifecycleUpdate() {
        IdentityAccount identity = persistDisabledIdentity();
        Instant activationTime = identity.getUpdatedAt().plusSeconds(1);
        identity.enable(provisioningActor(), "binding-migration-test", activationTime);

        identities.save(identity);
        entityManager.flush();
        entityManager.clear();

        IdentityAccount reloaded = identities.findById(identity.getId()).orElseThrow();
        assertEquals(IdentityAccountStatus.ACTIVE, reloaded.getStatus());
    }

    @Test
    void activeLegacySelfBindingIsQuarantinedByAuthenticationRules() {
        UUID identityId = UUID.randomUUID();
        Instant createdAt = Instant.parse("2026-08-19T08:00:00Z");
        entityManager.createNativeQuery("""
                INSERT INTO identity.identity_accounts (
                    id,
                    version,
                    subject_id,
                    actor_type,
                    login_identifier,
                    encoded_password,
                    status,
                    failed_authentication_attempts,
                    credentials_changed_at,
                    created_at,
                    updated_at
                ) VALUES (
                    :identityId,
                    0,
                    :identityId,
                    'RETAIL_CUSTOMER',
                    :loginIdentifier,
                    :encodedPassword,
                    'ACTIVE',
                    0,
                    :createdAt,
                    :createdAt,
                    :createdAt
                )
                """)
            .setParameter("identityId", identityId)
            .setParameter("loginIdentifier", "legacy-binding-" + identityId + "@example.invalid")
            .setParameter("encodedPassword", ENCODED_PASSWORD)
            .setParameter("createdAt", createdAt)
            .executeUpdate();
        entityManager.flush();
        entityManager.clear();

        IdentityAccount legacyIdentity = identities.findById(identityId).orElseThrow();

        assertEquals(IdentityAccountStatus.ACTIVE, legacyIdentity.getStatus());
        assertFalse(legacyIdentity.canAuthenticate(createdAt.plusSeconds(1)));
    }

    private IdentityAccount persistDisabledIdentity() {
        UUID identityId = UUID.randomUUID();
        IdentityAccount identity = IdentityAccount.provision(
            identityId,
            UUID.randomUUID(),
            IdentityActorType.RETAIL_CUSTOMER,
            "binding-" + identityId + "@example.invalid",
            EncodedPassword.fromPasswordEncoder(ENCODED_PASSWORD),
            provisioningActor(),
            "binding-migration-test",
            Instant.parse("2026-08-19T08:00:00Z")
        );
        identities.save(identity);
        entityManager.flush();
        entityManager.clear();
        return identities.findById(identityId).orElseThrow();
    }

    private static AuthenticationActor provisioningActor() {
        return AuthenticationActor.of(IdentityActorType.SERVICE_ACCOUNT, "synthetic-binding-test");
    }
}
