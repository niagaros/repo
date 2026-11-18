-- Zero Critical Issues (issue #296).
--
-- The scanners stay the source of truth for whether a problem exists. These tables only add what a scanner cannot
-- know: who owns a critical issue, its deadline, its remediation plan, a formally accepted risk, and the history of
-- every change. A critical issue is identified by (cloud_account_id, source, source_id): source is the table the
-- finding lives in (findings, ciem_findings, ai_inventory_findings), source_id its row id there. Those ids are stable
-- across scans (the scanners update rows in place), so ownership and history survive re-scans.
-- UUID keys: the runtime role cannot use admin-created sequences.

CREATE TABLE IF NOT EXISTS critical_issues (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    source             VARCHAR(24) NOT NULL CHECK (source IN ('findings', 'ciem_findings', 'ai_inventory_findings')),
    source_id          UUID        NOT NULL,
    title              TEXT        NOT NULL,
    -- Workflow status. Whether the problem still exists comes from the scanner at read time; 'resolved' is only set
    -- when a scan after the remediation no longer reports it (independent verification), never by a person.
    status             VARCHAR(24) NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'assigned', 'in_progress', 'remediated', 'resolved', 'reopened',
                          'accepted_risk', 'false_positive')),
    owner_email        TEXT,
    due_date           DATE,
    remediation_plan   TEXT,
    first_detected_at  TIMESTAMPTZ,
    last_observed_at   TIMESTAMPTZ,
    remediated_at      TIMESTAMPTZ,
    remediated_by      TEXT,
    resolved_at        TIMESTAMPTZ,
    verified_by_scan_at TIMESTAMPTZ,
    reopen_count       INTEGER     NOT NULL DEFAULT 0,
    escalated_at       TIMESTAMPTZ,
    -- Risk acceptance: every field the issue lists is mandatory, and it always expires.
    risk_justification TEXT,
    risk_rationale     TEXT,
    risk_owner         TEXT,
    risk_approver      TEXT,
    compensating_controls TEXT,
    residual_risk      TEXT,
    risk_expires_on    DATE,
    risk_review_every_days INTEGER,
    -- Acceptance is a request by one person and an approval by another; until approved the issue stays open.
    risk_approval      VARCHAR(12) CHECK (risk_approval IN ('pending', 'approved', 'rejected')),
    risk_requested_by  TEXT,
    risk_requested_at  TIMESTAMPTZ,
    risk_decided_at    TIMESTAMPTZ,
    false_positive_evidence TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cloud_account_id, source, source_id),
    CHECK (status <> 'accepted_risk' OR (risk_justification IS NOT NULL AND risk_owner IS NOT NULL
           AND risk_approver IS NOT NULL AND risk_expires_on IS NOT NULL AND compensating_controls IS NOT NULL
           AND risk_approval = 'approved' AND lower(risk_approver) <> lower(risk_requested_by))),
    CHECK (status <> 'false_positive' OR false_positive_evidence IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_critical_issues_account ON critical_issues (cloud_account_id, status);

-- Append-only history: every detection, assignment, plan, status change, verification, reopen and escalation.
CREATE TABLE IF NOT EXISTS critical_issue_events (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    issue_id           UUID        NOT NULL REFERENCES critical_issues(id) ON DELETE CASCADE,
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor              TEXT        NOT NULL,
    event              VARCHAR(40) NOT NULL,
    from_status        VARCHAR(24),
    to_status          VARCHAR(24),
    detail             JSONB       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_critical_issue_events_issue ON critical_issue_events (issue_id, at);
CREATE INDEX IF NOT EXISTS idx_critical_issue_events_account ON critical_issue_events (cloud_account_id, at DESC);

-- Per-account settings: remediation deadline for a new critical issue and how old evidence may be.
CREATE TABLE IF NOT EXISTS critical_issue_settings (
    cloud_account_id   UUID        PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    sla_days           INTEGER     NOT NULL DEFAULT 7  CHECK (sla_days BETWEEN 1 AND 90),
    freshness_days     INTEGER     NOT NULL DEFAULT 10 CHECK (freshness_days BETWEEN 1 AND 60),
    updated_by         TEXT,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One posture record per account per day, so the history of the zero-critical status can be reviewed.
CREATE TABLE IF NOT EXISTS critical_posture_snapshots (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id   UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    day                DATE        NOT NULL,
    status             VARCHAR(32) NOT NULL,
    open_critical      INTEGER     NOT NULL,
    accepted_critical  INTEGER     NOT NULL,
    overdue_critical   INTEGER     NOT NULL,
    evidence           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    recorded_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cloud_account_id, day)
);

-- The runtime role reads and writes these tables; history stays append-only for it.
GRANT SELECT, INSERT, UPDATE ON critical_issues, critical_issue_settings, critical_posture_snapshots TO cspm_lambda;
GRANT SELECT, INSERT ON critical_issue_events TO cspm_lambda;
-- Production default privileges also grant UPDATE/DELETE; the history must stay append-only.
REVOKE UPDATE, DELETE, TRUNCATE ON critical_issue_events FROM cspm_lambda;
REVOKE DELETE, TRUNCATE ON critical_issues FROM cspm_lambda;
