package com.quinnbank.core.identity.application.port;

import com.quinnbank.core.identity.application.result.AuthenticatedSubject;

import java.util.Optional;

/**
 * Resolves the business subject bound to the currently authenticated identity.
 */
public interface AuthenticatedSubjectProvider {
    Optional<AuthenticatedSubject> currentSubject();
}
