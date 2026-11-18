-- Niagaros Cloud Cost (issue #295): AWS billing ingestion, explorer, budgets, anomalies, idle-resource opportunities
-- with an approval/verification workflow, commitments. Scoped per cloud account so tenant_auth.guard applies.
-- Cost ingestion is opt-in per account: every AWS Cost Explorer request is billed to the customer ($0.01).
-- UUID keys: the runtime role cannot use admin-created sequences.

CREATE TABLE IF NOT EXISTS cost_settings (
    cloud_account_id   UUID        PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    enabled            BOOLEAN     NOT NULL DEFAULT false,
    enabled_by         TEXT,
    enabled_at         TIMESTAMPTZ,
    allocation_tag_key TEXT        CHECK (allocation_tag_key IS NULL OR length(allocation_tag_key) <= 128),
    anomaly_min_amount NUMERIC(12,2) NOT NULL DEFAULT 5 CHECK (anomaly_min_amount >= 0),
    updated_by         TEXT,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per ingestion run: what was read, what could not be read (opt-in features, access), and how many paid
-- Cost Explorer requests it made.
CREATE TABLE IF NOT EXISTS cost_ingestions (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    started_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at        TIMESTAMPTZ,
    status             VARCHAR(12) NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'succeeded', 'partial', 'failed')),
    trigger            VARCHAR(12) NOT NULL DEFAULT 'schedule' CHECK (trigger IN ('schedule', 'manual')),
    requested_by       TEXT,
    claimed_at         TIMESTAMPTZ,
    period_start       DATE,
    period_end         DATE,
    ce_requests        INTEGER     NOT NULL DEFAULT 0,
    coverage           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    error              TEXT,
    engine_version     TEXT
);
ALTER TABLE cost_ingestions ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_cost_ingestions_account ON cost_ingestions (cloud_account_id, started_at DESC);

-- Normalised daily cost per service and record type (Usage, Tax, Credit, Refund, ...). One current value per key;
-- every change by a later ingestion (late billing adjustments) is kept in cost_daily_revisions.
CREATE TABLE IF NOT EXISTS cost_daily (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    day                DATE        NOT NULL,
    service            TEXT        NOT NULL,
    record_type        TEXT        NOT NULL,
    amount             NUMERIC(18,6) NOT NULL,
    currency           VARCHAR(8)  NOT NULL,
    estimated          BOOLEAN     NOT NULL,
    source             TEXT        NOT NULL DEFAULT 'aws-cost-explorer',
    metric             TEXT        NOT NULL DEFAULT 'UnblendedCost',
    ingestion_id       UUID        REFERENCES cost_ingestions(id) ON DELETE SET NULL,
    first_ingested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cloud_account_id, day, service, record_type)
);
CREATE INDEX IF NOT EXISTS idx_cost_daily_account_day ON cost_daily (cloud_account_id, day);

CREATE TABLE IF NOT EXISTS cost_daily_revisions (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    day                DATE        NOT NULL,
    service            TEXT        NOT NULL,
    record_type        TEXT        NOT NULL,
    old_amount         NUMERIC(18,6) NOT NULL,
    new_amount         NUMERIC(18,6) NOT NULL,
    old_estimated      BOOLEAN,
    ingestion_id       UUID        REFERENCES cost_ingestions(id) ON DELETE SET NULL,
    changed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cost_revisions_account ON cost_daily_revisions (cloud_account_id, changed_at DESC);

-- Allocation by one cost-allocation tag; tag_value '' = untagged (unallocated) spend.
CREATE TABLE IF NOT EXISTS cost_allocation_daily (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    day                DATE        NOT NULL,
    tag_key            TEXT        NOT NULL,
    tag_value          TEXT        NOT NULL,
    amount             NUMERIC(18,6) NOT NULL,
    currency           VARCHAR(8)  NOT NULL,
    estimated          BOOLEAN     NOT NULL,
    ingestion_id       UUID        REFERENCES cost_ingestions(id) ON DELETE SET NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cloud_account_id, day, tag_key, tag_value)
);

-- AWS forecast as returned, per ingestion (history kept).
CREATE TABLE IF NOT EXISTS cost_forecasts (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    ingestion_id       UUID        REFERENCES cost_ingestions(id) ON DELETE CASCADE,
    period_start       DATE        NOT NULL,
    period_end         DATE        NOT NULL,
    mean_amount        NUMERIC(18,6) NOT NULL,
    currency           VARCHAR(8)  NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cost_forecasts_account ON cost_forecasts (cloud_account_id, created_at DESC);

-- Reservations / Savings Plans utilisation as read from Cost Explorer, per ingestion.
CREATE TABLE IF NOT EXISTS cost_commitment_snapshots (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    ingestion_id       UUID        REFERENCES cost_ingestions(id) ON DELETE CASCADE,
    kind               VARCHAR(16) NOT NULL CHECK (kind IN ('reservations', 'savings_plans')),
    available          BOOLEAN     NOT NULL,
    data               JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cost_budgets (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    name               TEXT        NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    monthly_amount     NUMERIC(14,2) NOT NULL CHECK (monthly_amount > 0),
    currency           VARCHAR(8)  NOT NULL DEFAULT 'USD',
    thresholds         INTEGER[]   NOT NULL DEFAULT '{50,80,100}',
    forecast_alert     BOOLEAN     NOT NULL DEFAULT true,
    active             BOOLEAN     NOT NULL DEFAULT true,
    created_by         TEXT        NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by         TEXT,
    updated_at         TIMESTAMPTZ
);

-- Budget threshold, forecast and anomaly alerts; acknowledged and resolved by people, never deleted.
CREATE TABLE IF NOT EXISTS cost_alerts (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    fingerprint        TEXT        NOT NULL,
    kind               VARCHAR(20) NOT NULL CHECK (kind IN ('budget_threshold', 'budget_forecast', 'anomaly', 'aws_anomaly')),
    title              TEXT        NOT NULL,
    amount             NUMERIC(18,6),
    detail             JSONB       NOT NULL DEFAULT '{}'::jsonb,
    status             VARCHAR(14) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_by    TEXT,
    acknowledged_at    TIMESTAMPTZ,
    resolved_by        TEXT,
    resolved_at        TIMESTAMPTZ,
    note               TEXT,
    UNIQUE (cloud_account_id, fingerprint)
);

-- Savings opportunities. Niagaros never executes them: observed -> approval_requested -> approved (second person)
-- -> executed (customer says it is done) -> verified (a later ingestion no longer finds the resource).
CREATE TABLE IF NOT EXISTS cost_opportunities (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    fingerprint        TEXT        NOT NULL,
    kind               VARCHAR(24) NOT NULL,
    region             TEXT,
    resource_id        TEXT        NOT NULL,
    title              TEXT        NOT NULL,
    monthly_savings    NUMERIC(14,2),
    savings_basis      TEXT        NOT NULL,
    confidence         VARCHAR(8)  NOT NULL,
    risk               VARCHAR(8)  NOT NULL,
    detail             JSONB       NOT NULL DEFAULT '{}'::jsonb,
    recommendation     TEXT,
    rollback           TEXT,
    status             VARCHAR(20) NOT NULL DEFAULT 'observed'
        CHECK (status IN ('observed', 'approval_requested', 'approved', 'executed', 'verified', 'dismissed', 'gone')),
    requested_by       TEXT,
    requested_at       TIMESTAMPTZ,
    approved_by        TEXT,
    approved_at        TIMESTAMPTZ,
    executed_by        TEXT,
    executed_at        TIMESTAMPTZ,
    execution_note     TEXT,
    verified_at        TIMESTAMPTZ,
    baseline_monthly   NUMERIC(14,2),
    dismissed_reason   TEXT,
    first_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cloud_account_id, fingerprint),
    CHECK (status <> 'approved' OR (approved_by IS NOT NULL AND lower(approved_by) <> lower(coalesce(requested_by, ''))))
);
CREATE INDEX IF NOT EXISTS idx_cost_opps_account ON cost_opportunities (cloud_account_id, status);

-- Who changed what (enable/disable, settings, budgets, alert decisions, approvals, executions, exports).
CREATE TABLE IF NOT EXISTS cost_audit_log (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    actor_email        TEXT        NOT NULL,
    action             TEXT        NOT NULL,
    target             TEXT,
    details            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cost_audit_account ON cost_audit_log (cloud_account_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE ON cost_settings, cost_ingestions, cost_daily, cost_allocation_daily, cost_forecasts,
    cost_commitment_snapshots, cost_budgets, cost_alerts, cost_opportunities TO cspm_lambda;
GRANT SELECT, INSERT ON cost_daily_revisions, cost_audit_log TO cspm_lambda;
-- Production default privileges also grant UPDATE/DELETE/TRUNCATE; history and audit stay append-only.
REVOKE UPDATE, DELETE, TRUNCATE ON cost_daily_revisions, cost_audit_log FROM cspm_lambda;
REVOKE DELETE, TRUNCATE ON cost_settings, cost_ingestions, cost_daily, cost_allocation_daily, cost_forecasts,
    cost_commitment_snapshots, cost_budgets, cost_alerts, cost_opportunities FROM cspm_lambda;
