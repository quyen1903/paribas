CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE identity.identity_accounts (
    id UUID NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    subject_id UUID NOT NULL,
    actor_type VARCHAR(30) NOT NULL,
    login_identifier VARCHAR(254) NOT NULL,
    encoded_password VARCHAR(500) NOT NULL,
    status VARCHAR(20) NOT NULL,
    failed_authentication_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP(6) WITH TIME ZONE,
    credentials_changed_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    last_authenticated_at TIMESTAMP(6) WITH TIME ZONE,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_identity_accounts PRIMARY KEY (id),
    CONSTRAINT uk_identity_accounts_actor_subject UNIQUE (actor_type, subject_id),
    CONSTRAINT uk_identity_accounts_login_identifier UNIQUE (login_identifier),
    CONSTRAINT ck_identity_accounts_version CHECK (version >= 0),
    CONSTRAINT ck_identity_accounts_actor_type CHECK (
        actor_type IN (
            'RETAIL_CUSTOMER',
            'BUSINESS_CUSTOMER',
            'BANK_EMPLOYEE',
            'BACK_OFFICE_OPERATOR'
        )
    ),
    CONSTRAINT ck_identity_accounts_status CHECK (
        status IN ('ACTIVE', 'DISABLED', 'CLOSED')
    ),
    CONSTRAINT ck_identity_accounts_login_identifier CHECK (
        login_identifier = LOWER(BTRIM(login_identifier))
        AND CHAR_LENGTH(login_identifier) BETWEEN 1 AND 254
    ),
    CONSTRAINT ck_identity_accounts_encoded_password CHECK (
        encoded_password ~ '^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$'
    ),
    CONSTRAINT ck_identity_accounts_failed_attempts CHECK (
        failed_authentication_attempts >= 0
    ),
    CONSTRAINT ck_identity_accounts_inactive_lock_state CHECK (
        status = 'ACTIVE'
        OR (failed_authentication_attempts = 0 AND locked_until IS NULL)
    ),
    CONSTRAINT ck_identity_accounts_timestamps CHECK (
        updated_at >= created_at
        AND credentials_changed_at >= created_at
        AND (last_authenticated_at IS NULL OR last_authenticated_at >= created_at)
    )
);

CREATE TABLE identity.authentication_audit_events (
    id UUID NOT NULL,
    target_identity_id UUID NOT NULL,
    actor_type VARCHAR(30) NOT NULL,
    actor_id VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    decision VARCHAR(20) NOT NULL,
    authentication_method VARCHAR(30),
    reason_code VARCHAR(64) NOT NULL,
    correlation_id VARCHAR(100) NOT NULL,
    occurred_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_authentication_audit_events PRIMARY KEY (id),
    CONSTRAINT fk_authentication_audit_target FOREIGN KEY (target_identity_id)
        REFERENCES identity.identity_accounts (id) ON DELETE RESTRICT,
    CONSTRAINT ck_authentication_audit_actor_type CHECK (
        actor_type IN (
            'RETAIL_CUSTOMER',
            'BUSINESS_CUSTOMER',
            'BANK_EMPLOYEE',
            'BACK_OFFICE_OPERATOR',
            'SERVICE_ACCOUNT',
            'THIRD_PARTY_PARTNER',
            'BATCH_JOB'
        )
    ),
    CONSTRAINT ck_authentication_audit_action CHECK (
        action IN (
            'ACCOUNT_PROVISIONED',
            'AUTHENTICATION_SUCCEEDED',
            'AUTHENTICATION_FAILED',
            'ACCOUNT_TEMPORARILY_LOCKED',
            'PASSWORD_CHANGED',
            'ACCOUNT_DISABLED',
            'ACCOUNT_ENABLED',
            'ACCOUNT_CLOSED'
        )
    ),
    CONSTRAINT ck_authentication_audit_decision CHECK (
        decision IN ('SUCCESS', 'FAILURE')
    ),
    CONSTRAINT ck_authentication_audit_method CHECK (
        authentication_method IS NULL OR authentication_method = 'PASSWORD'
    ),
    CONSTRAINT ck_authentication_audit_reason_code CHECK (
        reason_code ~ '^[A-Z0-9][A-Z0-9_]*$'
    ),
    CONSTRAINT ck_authentication_audit_correlation CHECK (
        correlation_id = BTRIM(correlation_id)
        AND CHAR_LENGTH(correlation_id) BETWEEN 1 AND 100
    )
);

CREATE INDEX idx_authentication_audit_target_time
    ON identity.authentication_audit_events (target_identity_id, occurred_at DESC);

CREATE INDEX idx_authentication_audit_actor_time
    ON identity.authentication_audit_events (actor_id, occurred_at DESC);

CREATE INDEX idx_authentication_audit_correlation
    ON identity.authentication_audit_events (correlation_id);

CREATE FUNCTION identity.prevent_authentication_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'authentication audit events are append-only';
END;
$$;

CREATE TRIGGER trg_prevent_authentication_audit_mutation
BEFORE UPDATE OR DELETE ON identity.authentication_audit_events
FOR EACH ROW
EXECUTE FUNCTION identity.prevent_authentication_audit_mutation();

CREATE FUNCTION identity.prevent_identity_account_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'identity accounts must be closed, not deleted';
END;
$$;

CREATE TRIGGER trg_prevent_identity_account_delete
BEFORE DELETE ON identity.identity_accounts
FOR EACH ROW
EXECUTE FUNCTION identity.prevent_identity_account_delete();
