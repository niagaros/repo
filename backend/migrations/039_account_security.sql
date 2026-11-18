-- Personal Privacy & Security (issue #291). Keyed by the Cognito user (sub), not by cloud account: these settings
-- belong to a person. Cognito stays the authority for passwords, TOTP, passkeys and email verification; these tables
-- hold what Cognito does not offer (security PIN, recovery codes), the sign-in sessions Niagaros has seen, and an
-- append-only history of security events. No secret is stored in plain text: PIN and codes are salted hashes.
-- UUID keys: the runtime role cannot use admin-created sequences.

CREATE TABLE IF NOT EXISTS account_security (
    user_sub           TEXT        PRIMARY KEY,
    email              TEXT        NOT NULL,
    pin_hash           BYTEA,
    pin_salt           BYTEA,
    pin_iterations     INTEGER,
    pin_set_at         TIMESTAMPTZ,
    pin_failed         INTEGER     NOT NULL DEFAULT 0,
    pin_locked_until   TIMESTAMPTZ,
    snapshot           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((pin_hash IS NULL) = (pin_salt IS NULL))
);

CREATE TABLE IF NOT EXISTS account_recovery_codes (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_sub           TEXT        NOT NULL,
    batch_id           UUID        NOT NULL,
    code_salt          BYTEA       NOT NULL,
    code_hash          BYTEA       NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at            TIMESTAMPTZ,
    superseded_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON account_recovery_codes (user_sub) WHERE used_at IS NULL AND superseded_at IS NULL;

-- Sign-in sessions seen by Niagaros (one per Cognito origin_jti), with the IP and browser the API observed.
CREATE TABLE IF NOT EXISTS account_sessions (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_sub           TEXT        NOT NULL,
    session_key        TEXT        NOT NULL,
    signed_in_at       TIMESTAMPTZ,
    first_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip                 TEXT,
    user_agent         TEXT,
    signed_out_at      TIMESTAMPTZ,
    UNIQUE (user_sub, session_key)
);

CREATE TABLE IF NOT EXISTS account_security_events (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_sub           TEXT,
    email              TEXT,
    at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event              VARCHAR(48) NOT NULL,
    outcome            VARCHAR(12) NOT NULL DEFAULT 'success' CHECK (outcome IN ('success', 'failure', 'observed')),
    detail             JSONB       NOT NULL DEFAULT '{}'::jsonb,
    ip                 TEXT,
    user_agent         TEXT,
    correlation_id     TEXT
);
CREATE INDEX IF NOT EXISTS idx_account_events_user ON account_security_events (user_sub, at DESC);

-- Attempts at the public recovery endpoint, for rate limiting (email stored as a hash only).
CREATE TABLE IF NOT EXISTS account_recovery_attempts (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email_hash         TEXT        NOT NULL,
    ip                 TEXT,
    at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    success            BOOLEAN     NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recovery_attempts ON account_recovery_attempts (email_hash, at DESC);
CREATE INDEX IF NOT EXISTS idx_recovery_attempts_ip ON account_recovery_attempts (ip, at DESC);

GRANT SELECT, INSERT, UPDATE ON account_security, account_recovery_codes, account_sessions TO cspm_lambda;
GRANT SELECT, INSERT ON account_security_events, account_recovery_attempts TO cspm_lambda;
-- Production default privileges also grant UPDATE/DELETE/TRUNCATE; history stays append-only.
REVOKE UPDATE, DELETE, TRUNCATE ON account_security_events, account_recovery_attempts FROM cspm_lambda;
REVOKE DELETE, TRUNCATE ON account_security, account_recovery_codes, account_sessions FROM cspm_lambda;
