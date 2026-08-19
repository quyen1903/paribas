ALTER TABLE identity.authentication_audit_events
    DROP CONSTRAINT ck_authentication_audit_action;

ALTER TABLE identity.authentication_audit_events
    ADD CONSTRAINT ck_authentication_audit_action CHECK (
        action IN (
            'ACCOUNT_PROVISIONED',
            'REGISTRATION_REJECTED',
            'AUTHENTICATION_SUCCEEDED',
            'AUTHENTICATION_FAILED',
            'AUTHORIZATION_DENIED',
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
