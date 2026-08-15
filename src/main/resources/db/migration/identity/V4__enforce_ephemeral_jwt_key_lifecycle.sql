UPDATE identity.jwt_signing_keys
SET version = version + 1,
    updated_at = GREATEST(updated_at, statement_timestamp());

ALTER TABLE identity.jwt_signing_keys
    DROP CONSTRAINT ck_jwt_signing_keys_status_state;

ALTER TABLE identity.jwt_signing_keys
    DROP CONSTRAINT ck_jwt_signing_keys_status;

ALTER TABLE identity.jwt_signing_keys
    ADD CONSTRAINT ck_jwt_signing_keys_status CHECK (
        status IN ('VERIFY_ONLY', 'REVOKED')
    );

ALTER TABLE identity.jwt_signing_keys
    ADD CONSTRAINT ck_jwt_signing_keys_status_state CHECK (
        (status = 'VERIFY_ONLY' AND verify_only_at IS NOT NULL AND revoked_at IS NULL)
        OR (status = 'REVOKED' AND revoked_at IS NOT NULL)
    );
