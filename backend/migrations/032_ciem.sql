-- CIEM: Cloud Infrastructure Entitlement Management (issue #17).
--
-- Scoped per cloud account (cloud_accounts.id), like every other scanner result, so tenant_auth.guard
-- applies unchanged. UUID keys: the runtime role cannot use admin-created sequences.

-- One row per collection run. Coverage and limitations say what was and was not analysed.
CREATE TABLE IF NOT EXISTS ciem_scans (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at       TIMESTAMPTZ,
    status            VARCHAR(12) NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'succeeded', 'partial', 'failed')),
    error             TEXT,
    trigger           VARCHAR(12) NOT NULL DEFAULT 'schedule' CHECK (trigger IN ('schedule', 'manual')),
    observation_days  INTEGER     NOT NULL DEFAULT 90,
    coverage          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    limitations       JSONB       NOT NULL DEFAULT '[]'::jsonb,
    summary           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    engine_version    TEXT,
    mapping_version   TEXT
);
CREATE INDEX IF NOT EXISTS idx_ciem_scans_account ON ciem_scans (cloud_account_id, started_at DESC);

-- Identity inventory per scan (history kept, so changes between scans can be shown).
CREATE TABLE IF NOT EXISTS ciem_identities (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id           UUID        NOT NULL REFERENCES ciem_scans(id) ON DELETE CASCADE,
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    arn               TEXT        NOT NULL,
    name              TEXT        NOT NULL,
    kind              VARCHAR(8)  NOT NULL CHECK (kind IN ('user', 'role', 'group')),
    classification    VARCHAR(16) NOT NULL,
    risk_score        INTEGER     NOT NULL DEFAULT 0,
    risk_severity     VARCHAR(8)  NOT NULL DEFAULT 'low',
    admin             VARCHAR(12),
    owner             TEXT,
    data              JSONB       NOT NULL,
    UNIQUE (scan_id, arn)
);
CREATE INDEX IF NOT EXISTS idx_ciem_identities_scan ON ciem_identities (scan_id);

-- Findings keep their identity across scans (fingerprint), so status, first/last seen and resolution survive.
CREATE TABLE IF NOT EXISTS ciem_findings (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    fingerprint       TEXT        NOT NULL,
    rule              TEXT        NOT NULL,
    category          TEXT        NOT NULL,
    severity          VARCHAR(8)  NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title             TEXT        NOT NULL,
    identity_arn      TEXT,
    identity_name     TEXT,
    details           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    recommendation    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    compliance        JSONB       NOT NULL DEFAULT '[]'::jsonb,
    status            VARCHAR(16) NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'in_progress', 'accepted', 'false_positive', 'resolved', 'suppressed')),
    status_reason     TEXT,
    status_by         TEXT,
    status_at         TIMESTAMPTZ,
    accepted_until    DATE,
    ticket            JSONB,
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at       TIMESTAMPTZ,
    last_scan_id      UUID        REFERENCES ciem_scans(id) ON DELETE SET NULL,
    UNIQUE (cloud_account_id, fingerprint),
    -- An accepted risk always has an end date and a reason (same rule as governance exceptions).
    CHECK (status <> 'accepted' OR (accepted_until IS NOT NULL AND status_reason IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_ciem_findings_account ON ciem_findings (cloud_account_id, status, severity);

-- Per-account settings: observation window and the built-in entitlement policy rules.
CREATE TABLE IF NOT EXISTS ciem_settings (
    cloud_account_id  UUID        PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    observation_days  INTEGER     NOT NULL DEFAULT 90 CHECK (observation_days IN (30, 60, 90, 180, 365)),
    rules             JSONB       NOT NULL DEFAULT '{}'::jsonb,
    updated_by        TEXT,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Access reviews: a reviewer decides per identity whether its access stays.
CREATE TABLE IF NOT EXISTS ciem_access_reviews (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    name              TEXT        NOT NULL,
    scope             TEXT        NOT NULL CHECK (scope IN ('privileged', 'machine', 'human', 'all')),
    reviewer_email    TEXT        NOT NULL,
    due_date          DATE        NOT NULL,
    status            VARCHAR(10) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'completed')),
    created_by        TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at      TIMESTAMPTZ,
    overdue_notified  BOOLEAN     NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS ciem_review_items (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id         UUID        NOT NULL REFERENCES ciem_access_reviews(id) ON DELETE CASCADE,
    identity_arn      TEXT        NOT NULL,
    identity_name     TEXT        NOT NULL,
    snapshot          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    decision          VARCHAR(12) CHECK (decision IN ('keep', 'reduce', 'remove')),
    note              TEXT,
    decided_by        TEXT,
    decided_at        TIMESTAMPTZ,
    UNIQUE (review_id, identity_arn)
);

-- Who did what in CIEM (status changes, settings, reviews, tickets, exports, manual scans).
CREATE TABLE IF NOT EXISTS ciem_audit_log (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    actor_email       TEXT,
    action            TEXT        NOT NULL,
    target            TEXT,
    details           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ciem_audit_account ON ciem_audit_log (cloud_account_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON ciem_scans, ciem_identities, ciem_findings, ciem_settings,
                                        ciem_access_reviews, ciem_review_items TO cspm_lambda;
GRANT SELECT, INSERT ON ciem_audit_log TO cspm_lambda;
-- Production default privileges also grant UPDATE/DELETE; the audit log must stay append-only.
REVOKE UPDATE, DELETE ON ciem_audit_log FROM cspm_lambda;
