package com.quinnbank.core.identity.application.port;

import com.quinnbank.core.identity.application.result.IssuedTokenPair;
import com.quinnbank.core.identity.application.result.VerifiedRefreshToken;
import com.quinnbank.core.identity.domain.AuthenticationSession;
import com.quinnbank.core.identity.domain.IdentityAccount;

import java.time.Instant;

public interface TokenPairService {
    IssuedTokenPair issuePair(
            IdentityAccount identityAccount,
            AuthenticationSession authenticationSession,
            Instant now
    );

    VerifiedRefreshToken verifyRefreshToken(String refreshToken);
}
