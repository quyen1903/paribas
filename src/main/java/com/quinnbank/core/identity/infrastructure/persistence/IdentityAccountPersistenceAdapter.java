package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.application.exception.IdentityProvisioningConflictException;
import com.quinnbank.core.identity.application.port.IdentityAccountRepository;
import com.quinnbank.core.identity.domain.IdentityAccount;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public class IdentityAccountPersistenceAdapter implements IdentityAccountRepository {
    private static final String UNIQUE_LOGIN_CONSTRAINT = "uk_identity_accounts_login_identifier";
    private static final String UNIQUE_ACTOR_SUBJECT_CONSTRAINT = "uk_identity_accounts_actor_subject";

    private final SpringDataIdentityAccountRepository repository;

    public IdentityAccountPersistenceAdapter(SpringDataIdentityAccountRepository repository) {
        this.repository = repository;
    }

    @Override
    public boolean existsByLoginIdentifier(String loginIdentifier) {
        return repository.existsByLoginIdentifier(loginIdentifier);
    }

    @Override
    public Optional<IdentityAccount> findByLoginIdentifierForUpdate(String loginIdentifier) {
        return repository.findByLoginIdentifierForUpdate(loginIdentifier);
    }

    @Override
    public Optional<IdentityAccount> findById(UUID identityId) {
        return repository.findById(identityId);
    }

    @Override
    public Optional<IdentityAccount> findByIdForUpdate(UUID identityId) {
        return repository.findByIdForUpdate(identityId);
    }

    @Override
    public Optional<IdentityAccount> findByActorTypeAndSubjectIdForUpdate(
        IdentityActorType actorType,
        UUID subjectId
    ) {
        return repository.findByActorTypeAndSubjectIdForUpdate(actorType, subjectId);
    }

    @Override
    public IdentityAccount save(IdentityAccount identityAccount) {
        try {
            return repository.saveAndFlush(identityAccount);
        } catch (DataIntegrityViolationException exception) {
            if (causedByIdentityUniquenessConstraint(exception)) {
                throw new IdentityProvisioningConflictException();
            }
            throw exception;
        }
    }

    private static boolean causedByIdentityUniquenessConstraint(Throwable failure) {
        Throwable current = failure;
        while (current != null) {
            if (current instanceof ConstraintViolationException constraintViolation
                    && isIdentityUniquenessConstraint(constraintViolation.getConstraintName())) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    private static boolean isIdentityUniquenessConstraint(String constraintName) {
        return UNIQUE_LOGIN_CONSTRAINT.equalsIgnoreCase(constraintName)
                || UNIQUE_ACTOR_SUBJECT_CONSTRAINT.equalsIgnoreCase(constraintName);
    }
}
