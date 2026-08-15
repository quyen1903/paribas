UPDATE identity.jwt_signing_keys
SET status = 'VERIFY_ONLY',
    verify_only_at = GREATEST(updated_at, statement_timestamp()),
    updated_at = GREATEST(updated_at, statement_timestamp())
WHERE status = 'ACTIVE';

DROP INDEX identity.uk_jwt_signing_keys_single_active;
