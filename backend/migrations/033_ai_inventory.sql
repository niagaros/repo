-- AI Inventory (issue #236). Scoped per cloud account like every other scanner result, so tenant_auth.guard
-- applies unchanged. UUID keys: the runtime role cannot use admin-created sequences.

CREATE TABLE IF NOT EXISTS ai_inventory_scans (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at       TIMESTAMPTZ,
    status            VARCHAR(12) NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'succeeded', 'partial', 'failed')),
    trigger           VARCHAR(12) NOT NULL DEFAULT 'schedule' CHECK (trigger IN ('schedule', 'manual')),
    error             TEXT,
    coverage          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    limitations       JSONB       NOT NULL DEFAULT '[]'::jsonb,
    summary           JSONB       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_ai_inv_scans_account ON ai_inventory_scans (cloud_account_id, started_at DESC);

-- One logical asset per stable key. Scans fill the "observed" columns; people fill the governance columns,
-- which a scan never overwrites.
CREATE TABLE IF NOT EXISTS ai_assets (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    asset_key         TEXT        NOT NULL,
    asset_type        TEXT        NOT NULL,
    name              TEXT        NOT NULL,
    provider          TEXT,
    verification      VARCHAR(12) NOT NULL DEFAULT 'declared'
        CHECK (verification IN ('unknown', 'declared', 'discovered', 'observed', 'verified')),
    metadata          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    metadata_hash     TEXT,
    origin            VARCHAR(10) NOT NULL DEFAULT 'discovered' CHECK (origin IN ('discovered', 'manual', 'imported')),
    -- governance (people)
    owner             TEXT,
    business_purpose  TEXT,
    environment       VARCHAR(12) NOT NULL DEFAULT 'unknown' CHECK (environment IN ('unknown', 'production', 'staging', 'development', 'test')),
    criticality       VARCHAR(8)  NOT NULL DEFAULT 'unknown' CHECK (criticality IN ('unknown', 'low', 'medium', 'high', 'critical')),
    approval_status   VARCHAR(12) NOT NULL DEFAULT 'unreviewed'
        CHECK (approval_status IN ('unreviewed', 'approved', 'restricted', 'rejected', 'exception')),
    approval_reason   TEXT,
    approval_by       TEXT,
    approval_at       TIMESTAMPTZ,
    approval_until    DATE,
    lifecycle_status  VARCHAR(14) NOT NULL DEFAULT 'active'
        CHECK (lifecycle_status IN ('active', 'stale', 'inactive', 'deprecated', 'retired')),
    next_review_at    DATE,
    -- observation timestamps (kept distinct, as the issue asks)
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_synced       TIMESTAMPTZ,
    last_verified     TIMESTAMPTZ,
    UNIQUE (cloud_account_id, asset_key),
    CHECK (approval_status <> 'exception' OR (approval_until IS NOT NULL AND approval_reason IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_ai_assets_account ON ai_assets (cloud_account_id, asset_type);

-- Where and when each asset was seen. Evidence references only; no secret values, no prompt text.
CREATE TABLE IF NOT EXISTS ai_asset_observations (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id          UUID        NOT NULL REFERENCES ai_assets(id) ON DELETE CASCADE,
    scan_id           UUID        REFERENCES ai_inventory_scans(id) ON DELETE SET NULL,
    source            TEXT        NOT NULL,
    ref               TEXT,
    verification      VARCHAR(12) NOT NULL,
    observed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ai_obs_asset ON ai_asset_observations (asset_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS ai_asset_relationships (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    source_asset_id   UUID        NOT NULL REFERENCES ai_assets(id) ON DELETE CASCADE,
    target_asset_id   UUID        NOT NULL REFERENCES ai_assets(id) ON DELETE CASCADE,
    rel_type          TEXT        NOT NULL,
    sources           JSONB       NOT NULL DEFAULT '[]'::jsonb,
    verification      VARCHAR(12) NOT NULL,
    confidence        VARCHAR(8)  NOT NULL DEFAULT 'high',
    note              TEXT,
    origin            VARCHAR(10) NOT NULL DEFAULT 'discovered' CHECK (origin IN ('discovered', 'manual')),
    created_by        TEXT,
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_asset_id, target_asset_id, rel_type)
);
CREATE INDEX IF NOT EXISTS idx_ai_rel_account ON ai_asset_relationships (cloud_account_id);

-- Detected and manual changes, with the previous and new value. History outlives a deleted asset: the
-- reference is cleared and the name is kept (filled in on insert by the trigger below).
CREATE TABLE IF NOT EXISTS ai_asset_changes (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    asset_id          UUID        REFERENCES ai_assets(id) ON DELETE SET NULL,
    asset_name        TEXT,
    change_type       TEXT        NOT NULL,
    previous          JSONB,
    new               JSONB,
    source            TEXT        NOT NULL,
    actor             TEXT,
    risk_impact       VARCHAR(8),
    detected_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ai_changes_account ON ai_asset_changes (cloud_account_id, detected_at DESC);

CREATE OR REPLACE FUNCTION ai_asset_changes_name() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.asset_name IS NULL AND NEW.asset_id IS NOT NULL THEN
        SELECT name INTO NEW.asset_name FROM ai_assets WHERE id = NEW.asset_id;
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_ai_asset_changes_name ON ai_asset_changes;
CREATE TRIGGER trg_ai_asset_changes_name BEFORE INSERT ON ai_asset_changes
    FOR EACH ROW EXECUTE FUNCTION ai_asset_changes_name();

CREATE TABLE IF NOT EXISTS ai_inventory_findings (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    fingerprint       TEXT        NOT NULL,
    asset_id          UUID        REFERENCES ai_assets(id) ON DELETE SET NULL,
    rule              TEXT        NOT NULL,
    severity          VARCHAR(8)  NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title             TEXT        NOT NULL,
    details           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    recommendation    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    compliance        JSONB       NOT NULL DEFAULT '[]'::jsonb,
    status            VARCHAR(16) NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'in_progress', 'accepted', 'false_positive', 'resolved')),
    status_reason     TEXT,
    status_by         TEXT,
    status_at         TIMESTAMPTZ,
    accepted_until    DATE,
    ticket            JSONB,
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at       TIMESTAMPTZ,
    UNIQUE (cloud_account_id, fingerprint),
    CHECK (status <> 'accepted' OR (accepted_until IS NOT NULL AND status_reason IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS ai_inventory_settings (
    cloud_account_id    UUID        PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    approved_providers  JSONB       NOT NULL DEFAULT '[]'::jsonb,
    github_repos        JSONB       NOT NULL DEFAULT '[]'::jsonb,
    inactive_after_days INTEGER     NOT NULL DEFAULT 30 CHECK (inactive_after_days BETWEEN 7 AND 365),
    updated_by          TEXT,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ai_inventory_audit_log (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    actor_email       TEXT,
    action            TEXT        NOT NULL,
    target            TEXT,
    details           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ai_audit_account ON ai_inventory_audit_log (cloud_account_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON ai_inventory_scans, ai_assets, ai_asset_observations, ai_asset_relationships,
                                        ai_inventory_findings, ai_inventory_settings TO cspm_lambda;
GRANT SELECT, INSERT ON ai_asset_changes, ai_inventory_audit_log TO cspm_lambda;
-- Production default privileges also grant UPDATE/DELETE; change history and audit log stay append-only.
REVOKE UPDATE, DELETE ON ai_asset_changes, ai_inventory_audit_log FROM cspm_lambda;
