ALTER TABLE identity.authentication_audit_events
    ALTER COLUMN target_identity_id DROP NOT NULL;

ALTER TABLE identity.authentication_audit_events
    DROP CONSTRAINT ck_authentication_audit_action;

ALTER TABLE identity.authentication_audit_events
    ADD CONSTRAINT ck_authentication_audit_action CHECK (
        action IN (
            'ACCOUNT_PROVISIONED',
            'REGISTRATION_REJECTED',
            'AUTHENTICATION_SUCCEEDED',
            'AUTHENTICATION_FAILED',
            'ACCOUNT_TEMPORARILY_LOCKED',
            'PASSWORD_CHANGED',
            'ACCOUNT_DISABLED',
            'ACCOUNT_ENABLED',
            'ACCOUNT_CLOSED',
            'TOKEN_PAIR_ISSUED',
            'TOKEN_REFRESHED',
            'TOKEN_REFRESH_REJECTED',
            'REFRESH_TOKEN_REPLAY_DETECTED',
            'SESSION_REVOKED'
        )
    );

ALTER TABLE identity.authentication_audit_events
    DROP CONSTRAINT ck_authentication_audit_method;

ALTER TABLE identity.authentication_audit_events
    ADD CONSTRAINT ck_authentication_audit_method CHECK (
        authentication_method IS NULL
        OR authentication_method IN ('PASSWORD', 'JWT')
    );

CREATE TABLE identity.jwt_signing_keys (
    key_id VARCHAR(100) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    algorithm VARCHAR(10) NOT NULL,
    public_key_der BYTEA NOT NULL,
    public_key_sha256 VARCHAR(64) NOT NULL,
    status VARCHAR(20) NOT NULL,
    verify_only_at TIMESTAMP(6) WITH TIME ZONE,
    revoked_at TIMESTAMP(6) WITH TIME ZONE,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_jwt_signing_keys PRIMARY KEY (key_id),
    CONSTRAINT ck_jwt_signing_keys_version CHECK (version >= 0),
    CONSTRAINT ck_jwt_signing_keys_key_id CHECK (
        key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$'
    ),
    CONSTRAINT ck_jwt_signing_keys_algorithm CHECK (algorithm = 'RS256'),
    CONSTRAINT ck_jwt_signing_keys_public_key_size CHECK (
        OCTET_LENGTH(public_key_der) BETWEEN 384 AND 16384
    ),
    CONSTRAINT ck_jwt_signing_keys_fingerprint CHECK (
        public_key_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_jwt_signing_keys_status CHECK (
        status IN ('ACTIVE', 'VERIFY_ONLY', 'REVOKED')
    ),
    CONSTRAINT ck_jwt_signing_keys_status_state CHECK (
        (status = 'ACTIVE' AND verify_only_at IS NULL AND revoked_at IS NULL)
        OR (status = 'VERIFY_ONLY' AND verify_only_at IS NOT NULL AND revoked_at IS NULL)
        OR (status = 'REVOKED' AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT ck_jwt_signing_keys_timestamps CHECK (
        updated_at >= created_at
        AND (verify_only_at IS NULL OR verify_only_at >= created_at)
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    )
);

CREATE UNIQUE INDEX uk_jwt_signing_keys_single_active
    ON identity.jwt_signing_keys ((1))
    WHERE status = 'ACTIVE';

CREATE INDEX idx_jwt_signing_keys_status
    ON identity.jwt_signing_keys (status);

CREATE TABLE identity.jwt_signing_key_audit_events (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY,
    key_id VARCHAR(100) NOT NULL,
    event_type VARCHAR(20) NOT NULL,
    previous_status VARCHAR(20),
    new_status VARCHAR(20) NOT NULL,
    occurred_at TIMESTAMP(6) WITH TIME ZONE NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_jwt_signing_key_audit_events PRIMARY KEY (audit_id),
    CONSTRAINT fk_jwt_signing_key_audit_key FOREIGN KEY (key_id)
        REFERENCES identity.jwt_signing_keys (key_id) ON DELETE RESTRICT,
    CONSTRAINT ck_jwt_signing_key_audit_event_type CHECK (
        event_type IN ('REGISTERED', 'STATUS_CHANGED')
    ),
    CONSTRAINT ck_jwt_signing_key_audit_previous_status CHECK (
        previous_status IS NULL
        OR previous_status IN ('ACTIVE', 'VERIFY_ONLY', 'REVOKED')
    ),
    CONSTRAINT ck_jwt_signing_key_audit_new_status CHECK (
        new_status IN ('ACTIVE', 'VERIFY_ONLY', 'REVOKED')
    )
);

CREATE INDEX idx_jwt_signing_key_audit_key_time
    ON identity.jwt_signing_key_audit_events (key_id, occurred_at DESC);

CREATE FUNCTION identity.enforce_jwt_signing_key_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.key_id IS DISTINCT FROM OLD.key_id
        OR NEW.algorithm IS DISTINCT FROM OLD.algorithm
        OR NEW.public_key_der IS DISTINCT FROM OLD.public_key_der
        OR NEW.public_key_sha256 IS DISTINCT FROM OLD.public_key_sha256
        OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'JWT signing key identity and public material are immutable';
    END IF;

    IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
        IF NEW.verify_only_at IS DISTINCT FROM OLD.verify_only_at
            OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
            RAISE EXCEPTION 'JWT signing key lifecycle timestamps require a status transition';
        END IF;
        RETURN NEW;
    END IF;

    IF NOT (
        (OLD.status = 'ACTIVE' AND NEW.status IN ('VERIFY_ONLY', 'REVOKED'))
        OR (OLD.status = 'VERIFY_ONLY' AND NEW.status = 'REVOKED')
    ) THEN
        RAISE EXCEPTION 'invalid JWT signing key status transition from % to %', OLD.status, NEW.status;
    END IF;

    IF OLD.status = 'ACTIVE' AND NEW.status = 'VERIFY_ONLY'
        AND (NEW.verify_only_at IS NULL OR NEW.revoked_at IS NOT NULL) THEN
        RAISE EXCEPTION 'verify-only transition requires verify_only_at only';
    END IF;

    IF NEW.status = 'REVOKED'
        AND (NEW.revoked_at IS NULL OR NEW.verify_only_at IS DISTINCT FROM OLD.verify_only_at) THEN
        RAISE EXCEPTION 'revocation requires revoked_at and cannot rewrite verify_only_at';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_enforce_jwt_signing_key_lifecycle
BEFORE UPDATE ON identity.jwt_signing_keys
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_jwt_signing_key_lifecycle();

CREATE FUNCTION identity.prevent_jwt_signing_key_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'JWT signing keys must be revoked, not deleted';
END;
$$;

CREATE TRIGGER trg_prevent_jwt_signing_key_delete
BEFORE DELETE ON identity.jwt_signing_keys
FOR EACH ROW
EXECUTE FUNCTION identity.prevent_jwt_signing_key_delete();

CREATE FUNCTION identity.audit_jwt_signing_key_status()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO identity.jwt_signing_key_audit_events (
            key_id,
            event_type,
            previous_status,
            new_status
        ) VALUES (
            NEW.key_id,
            'REGISTERED',
            NULL,
            NEW.status
        );
    ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO identity.jwt_signing_key_audit_events (
            key_id,
            event_type,
            previous_status,
            new_status
        ) VALUES (
            NEW.key_id,
            'STATUS_CHANGED',
            OLD.status,
            NEW.status
        );
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_jwt_signing_key_status
AFTER INSERT OR UPDATE ON identity.jwt_signing_keys
FOR EACH ROW
EXECUTE FUNCTION identity.audit_jwt_signing_key_status();

CREATE FUNCTION identity.prevent_jwt_signing_key_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'JWT signing key audit events are append-only';
END;
$$;

CREATE TRIGGER trg_prevent_jwt_signing_key_audit_mutation
BEFORE UPDATE OR DELETE ON identity.jwt_signing_key_audit_events
FOR EACH ROW
EXECUTE FUNCTION identity.prevent_jwt_signing_key_audit_mutation();

CREATE TABLE identity.authentication_sessions (
    id UUID NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    identity_account_id UUID NOT NULL,
    current_refresh_token_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL,
    expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP(6) WITH TIME ZONE,
    revocation_reason_code VARCHAR(64),
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_authentication_sessions PRIMARY KEY (id),
    CONSTRAINT fk_authentication_sessions_identity FOREIGN KEY (identity_account_id)
        REFERENCES identity.identity_accounts (id) ON DELETE RESTRICT,
    CONSTRAINT uk_authentication_sessions_refresh_token_id UNIQUE (current_refresh_token_id),
    CONSTRAINT ck_authentication_sessions_version CHECK (version >= 0),
    CONSTRAINT ck_authentication_sessions_status CHECK (
        status IN ('ACTIVE', 'REVOKED')
    ),
    CONSTRAINT ck_authentication_sessions_status_state CHECK (
        (status = 'ACTIVE' AND revoked_at IS NULL AND revocation_reason_code IS NULL)
        OR (status = 'REVOKED' AND revoked_at IS NOT NULL AND revocation_reason_code IS NOT NULL)
    ),
    CONSTRAINT ck_authentication_sessions_reason_code CHECK (
        revocation_reason_code IS NULL
        OR revocation_reason_code ~ '^[A-Z0-9][A-Z0-9_]*$'
    ),
    CONSTRAINT ck_authentication_sessions_timestamps CHECK (
        expires_at > created_at
        AND updated_at >= created_at
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    )
);

CREATE INDEX idx_authentication_sessions_identity_status
    ON identity.authentication_sessions (identity_account_id, status);

CREATE INDEX idx_authentication_sessions_active_expiry
    ON identity.authentication_sessions (expires_at)
    WHERE status = 'ACTIVE';
