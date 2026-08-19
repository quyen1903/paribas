package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.application.exception.IdentityProvisioningConflictException;
import com.quinnbank.core.identity.domain.IdentityAccount;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IdentityAccountPersistenceAdapterTest {
    @Test
    void translatesBothLoginAndCustomerSubjectRacesToTheSameSafeConflict() {
        assertIdentityConflict("uk_identity_accounts_login_identifier");
        assertIdentityConflict("uk_identity_accounts_actor_subject");
    }

    @Test
    void preservesUnrelatedPersistenceFailures() {
        SpringDataIdentityAccountRepository repository = mock(SpringDataIdentityAccountRepository.class);
        IdentityAccount identity = mock(IdentityAccount.class);
        DataIntegrityViolationException failure = constraintFailure("unrelated_constraint");
        when(repository.saveAndFlush(identity)).thenThrow(failure);

        DataIntegrityViolationException thrown = assertThrows(
            DataIntegrityViolationException.class,
            () -> new IdentityAccountPersistenceAdapter(repository).save(identity)
        );

        assertSame(failure, thrown);
    }

    private static void assertIdentityConflict(String constraintName) {
        SpringDataIdentityAccountRepository repository = mock(SpringDataIdentityAccountRepository.class);
        IdentityAccount identity = mock(IdentityAccount.class);
        when(repository.saveAndFlush(identity)).thenThrow(constraintFailure(constraintName));

        assertThrows(
            IdentityProvisioningConflictException.class,
            () -> new IdentityAccountPersistenceAdapter(repository).save(identity)
        );
    }

    private static DataIntegrityViolationException constraintFailure(String constraintName) {
        ConstraintViolationException cause = new ConstraintViolationException(
            "synthetic constraint violation",
            new SQLException("synthetic database failure"),
            constraintName
        );
        return new DataIntegrityViolationException("synthetic data-integrity failure", cause);
    }
}
