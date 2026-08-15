package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.domain.JwtSigningKey;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtSigningKeyPersistenceAdapterTest {
    @Test
    void savesVerificationKeyWithoutForcingARotationFlush() {
        SpringDataJwtSigningKeyRepository springDataRepository =
                mock(SpringDataJwtSigningKeyRepository.class);
        JwtSigningKey signingKey = mock(JwtSigningKey.class);
        JwtSigningKeyPersistenceAdapter adapter =
                new JwtSigningKeyPersistenceAdapter(springDataRepository);
        when(springDataRepository.save(signingKey)).thenReturn(signingKey);

        JwtSigningKey saved = adapter.save(signingKey);

        assertSame(signingKey, saved);
        verify(springDataRepository).save(signingKey);
        verify(springDataRepository, never()).saveAndFlush(signingKey);
    }
}
