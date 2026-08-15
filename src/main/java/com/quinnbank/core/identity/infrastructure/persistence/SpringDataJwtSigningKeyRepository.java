package com.quinnbank.core.identity.infrastructure.persistence;

import com.quinnbank.core.identity.domain.JwtSigningKey;
import org.springframework.data.jpa.repository.JpaRepository;

interface SpringDataJwtSigningKeyRepository extends JpaRepository<JwtSigningKey, String> {
}
