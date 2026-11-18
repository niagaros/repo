-- Security Agents: Red / Blue / Green (issue #239). Scoped per cloud account like every other scanner result,
-- so tenant_auth.guard applies unchanged. UUID keys: the runtime role cannot use admin-created sequences.

CREATE TABLE IF NOT EXISTS sa_settings (
    cloud_account_id  UUID        PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    environment       VARCHAR(12) NOT NULL DEFAULT 'production' CHECK (environment IN ('production', 'staging', 'development', 'test')),
    lookback_hours    INTEGER     NOT NULL DEFAULT 24 CHECK (lookback_hours BETWEEN 1 AND 2160),
    updated_by        TEXT,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Registry: one row per built-in agent per account (agents themselves are versioned in code).
CREATE TABLE IF NOT EXISTS sa_agents (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    agent_id          TEXT        NOT NULL,
    status            VARCHAR(12) NOT NULL DEFAULT 'registered'
        CHECK (status IN ('registered', 'configured', 'tested', 'approved', 'active', 'paused', 'restricted', 'deprecated', 'retired')),
    owner             TEXT,
    business_purpose  TEXT,
    approved_by       TEXT,
    approved_at       TIMESTAMPTZ,
    agent_version     TEXT,
    last_run_at       TIMESTAMPTZ,
    last_run_status   TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cloud_account_id, agent_id)
);

CREATE TABLE IF NOT EXISTS sa_authorizations (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    agent_id          TEXT        NOT NULL,
    scope_type        VARCHAR(10) NOT NULL DEFAULT 'account' CHECK (scope_type IN ('account')),
    scope_reference   TEXT        NOT NULL,
    environments      JSONB       NOT NULL DEFAULT '[]'::jsonb,
    allowed_actions   JSONB       NOT NULL DEFAULT '[]'::jsonb,
    prohibited_actions JSONB      NOT NULL DEFAULT '[]'::jsonb,
    valid_from        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until       TIMESTAMPTZ NOT NULL,
    reason            TEXT,
    approved_by       TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at        TIMESTAMPTZ,
    revoked_by        TEXT,
    CHECK (valid_until > valid_from)
);
CREATE INDEX IF NOT EXISTS idx_sa_auth_account ON sa_authorizations (cloud_account_id, agent_id);

-- Autonomy per agent, action and environment (issue §7).
CREATE TABLE IF NOT EXISTS sa_policies (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    agent_id          TEXT        NOT NULL,
    action            TEXT        NOT NULL,
    environment       VARCHAR(12) NOT NULL,
    level             VARCHAR(2)  NOT NULL CHECK (level IN ('L0', 'L1', 'L2', 'L3', 'L4', 'L5')),
    requires_approval BOOLEAN     NOT NULL DEFAULT TRUE,
    updated_by        TEXT,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cloud_account_id, agent_id, action, environment)
);

CREATE TABLE IF NOT EXISTS sa_runs (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    workflow_id       UUID        NOT NULL,
    agent_id          TEXT        NOT NULL,
    agent_version     TEXT        NOT NULL,
    trigger           VARCHAR(12) NOT NULL DEFAULT 'schedule' CHECK (trigger IN ('schedule', 'manual', 'event')),
    initiated_by      TEXT,
    policy_version    TEXT        NOT NULL,
    scope_snapshot    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    status            VARCHAR(12) NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'succeeded', 'partial', 'failed', 'blocked', 'cancelled')),
    started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at      TIMESTAMPTZ,
    resource_usage    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    coverage          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    limitations       JSONB       NOT NULL DEFAULT '[]'::jsonb,
    summary           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    error             TEXT
);
CREATE INDEX IF NOT EXISTS idx_sa_runs_account ON sa_runs (cloud_account_id, started_at DESC);

-- Every requested action with its execution-time authorisation decision, including blocked ones.
CREATE TABLE IF NOT EXISTS sa_actions (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    run_id            UUID        REFERENCES sa_runs(id) ON DELETE SET NULL,
    agent_id          TEXT        NOT NULL,
    action            TEXT        NOT NULL,
    target            TEXT,
    environment       VARCHAR(12),
    decision          VARCHAR(18) NOT NULL CHECK (decision IN ('allow', 'approval_required', 'block')),
    reason            TEXT,
    execution_status  VARCHAR(12) NOT NULL DEFAULT 'not_started'
        CHECK (execution_status IN ('not_started', 'succeeded', 'failed', 'skipped', 'waiting')),
    approval_id       UUID,
    initiated_by      TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sa_actions_account ON sa_actions (cloud_account_id, created_at DESC);

-- Unified queue across Red, Blue and Green (issue §11).
CREATE TABLE IF NOT EXISTS sa_work_items (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    fingerprint       TEXT        NOT NULL,
    agent_id          TEXT        NOT NULL,
    category          VARCHAR(5)  NOT NULL CHECK (category IN ('red', 'blue', 'green')),
    source_type       TEXT        NOT NULL,
    source_id         TEXT        NOT NULL,
    title             TEXT        NOT NULL,
    severity          VARCHAR(8)  NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence        VARCHAR(6)  NOT NULL,
    priority          INTEGER     NOT NULL DEFAULT 0,
    priority_reasons  JSONB       NOT NULL DEFAULT '[]'::jsonb,
    basis             TEXT,
    evidence          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    assets            JSONB       NOT NULL DEFAULT '[]'::jsonb,
    recommendation    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    attack_path       JSONB,
    validation        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    active_threat     BOOLEAN     NOT NULL DEFAULT FALSE,
    state             VARCHAR(18) NOT NULL DEFAULT 'new'
        CHECK (state IN ('new', 'triaged', 'assigned', 'in_progress', 'awaiting_approval', 'remediated', 'verification',
                         'resolved', 'blocked', 'accepted_risk', 'false_positive', 'reopened')),
    state_reason      TEXT,
    owner             TEXT,
    due_at            DATE,
    accepted_until    DATE,
    plan              JSONB,
    change_reference  TEXT,
    remediated_at     TIMESTAMPTZ,
    remediated_by     TEXT,
    verification      JSONB,
    ticket            JSONB,
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at       TIMESTAMPTZ,
    UNIQUE (cloud_account_id, fingerprint),
    CHECK (state <> 'accepted_risk' OR (accepted_until IS NOT NULL AND state_reason IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_sa_items_account ON sa_work_items (cloud_account_id, state, priority DESC);

CREATE TABLE IF NOT EXISTS sa_work_item_events (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    work_item_id      UUID        NOT NULL REFERENCES sa_work_items(id) ON DELETE CASCADE,
    from_state        TEXT,
    to_state          TEXT,
    actor             TEXT        NOT NULL,
    actor_kind        VARCHAR(6)  NOT NULL CHECK (actor_kind IN ('human', 'agent')),
    note              TEXT,
    details           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sa_item_events ON sa_work_item_events (work_item_id, created_at);

CREATE TABLE IF NOT EXISTS sa_incidents (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    fingerprint       TEXT        NOT NULL,
    principal         TEXT        NOT NULL,
    severity          VARCHAR(8)  NOT NULL,
    summary           TEXT        NOT NULL,
    hypothesis        TEXT,
    basis             TEXT,
    resources         JSONB       NOT NULL DEFAULT '[]'::jsonb,
    related_work_items JSONB      NOT NULL DEFAULT '[]'::jsonb,
    status            VARCHAR(14) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'contained', 'closed')),
    status_reason     TEXT,
    owner             TEXT,
    first_event_at    TIMESTAMPTZ NOT NULL,
    last_event_at     TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cloud_account_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS sa_detections (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    fingerprint       TEXT        NOT NULL,
    run_id            UUID        REFERENCES sa_runs(id) ON DELETE SET NULL,
    incident_id       UUID        REFERENCES sa_incidents(id) ON DELETE SET NULL,
    rule              TEXT        NOT NULL,
    agent_id          TEXT        NOT NULL,
    severity          VARCHAR(8)  NOT NULL,
    title             TEXT        NOT NULL,
    mitre             TEXT,
    principal         TEXT,
    resources         JSONB       NOT NULL DEFAULT '[]'::jsonb,
    source_ip         TEXT,
    region            TEXT,
    first_event_at    TIMESTAMPTZ NOT NULL,
    last_event_at     TIMESTAMPTZ NOT NULL,
    event_count       INTEGER     NOT NULL DEFAULT 1,
    event_ids         JSONB       NOT NULL DEFAULT '[]'::jsonb,
    event_names       JSONB       NOT NULL DEFAULT '[]'::jsonb,
    why               TEXT,
    respond           TEXT,
    status            VARCHAR(12) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'benign', 'escalated')),
    status_reason     TEXT,
    status_by         TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cloud_account_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_sa_det_account ON sa_detections (cloud_account_id, first_event_at DESC);

CREATE TABLE IF NOT EXISTS sa_approvals (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    agent_id          TEXT        NOT NULL,
    action            TEXT        NOT NULL,
    work_item_id      UUID        REFERENCES sa_work_items(id) ON DELETE CASCADE,
    incident_id       UUID        REFERENCES sa_incidents(id) ON DELETE CASCADE,
    target            TEXT,
    payload           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    requested_by      TEXT        NOT NULL,
    decision          VARCHAR(10) NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending', 'approved', 'rejected', 'expired')),
    decided_by        TEXT,
    reason            TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL,
    decided_at        TIMESTAMPTZ,
    executed_at       TIMESTAMPTZ,
    execution_result  JSONB
);
CREATE INDEX IF NOT EXISTS idx_sa_appr_account ON sa_approvals (cloud_account_id, decision, created_at DESC);

CREATE TABLE IF NOT EXISTS sa_evidence (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    run_id            UUID        REFERENCES sa_runs(id) ON DELETE SET NULL,
    work_item_id      UUID        REFERENCES sa_work_items(id) ON DELETE SET NULL,
    evidence_type     TEXT        NOT NULL,
    source_reference  TEXT        NOT NULL,
    content_hash      TEXT        NOT NULL,
    summary           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    verification_status VARCHAR(10) NOT NULL DEFAULT 'observed' CHECK (verification_status IN ('observed', 'calculated', 'correlated', 'hypothesis', 'verified')),
    collected_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sa_evidence_item ON sa_evidence (work_item_id, collected_at DESC);

CREATE TABLE IF NOT EXISTS sa_evaluations (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    agent_id          TEXT        NOT NULL,
    agent_version     TEXT        NOT NULL,
    passed            BOOLEAN     NOT NULL,
    result            JSONB       NOT NULL,
    run_by            TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sa_eval_agent ON sa_evaluations (cloud_account_id, agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS sa_audit_log (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    actor_email       TEXT,
    action            TEXT        NOT NULL,
    target            TEXT,
    details           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sa_audit_account ON sa_audit_log (cloud_account_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON sa_settings, sa_agents, sa_authorizations, sa_policies, sa_runs, sa_actions,
                                        sa_work_items, sa_incidents, sa_detections, sa_approvals, sa_evaluations TO cspm_lambda;
GRANT SELECT, INSERT ON sa_work_item_events, sa_evidence, sa_audit_log TO cspm_lambda;
-- Production default privileges also grant UPDATE/DELETE; history, evidence and audit log stay append-only.
REVOKE UPDATE, DELETE, TRUNCATE ON sa_work_item_events, sa_evidence, sa_audit_log FROM cspm_lambda;
