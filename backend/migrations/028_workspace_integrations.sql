-- Jira / Monday integrations (issue #279). Applied via integrations-handler {"action":"migrate"}.
CREATE TABLE IF NOT EXISTS workspace_integrations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL CHECK (provider IN ('jira', 'monday')),
    site_url         TEXT,
    account_label    TEXT,
    account_email    TEXT,
    project          TEXT,
    secret_name      TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_sync_at     TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS integration_tickets (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id   UUID NOT NULL REFERENCES workspace_integrations(id) ON DELETE CASCADE,
    audit_finding_id UUID NOT NULL REFERENCES audit_findings(id) ON DELETE CASCADE,
    external_id      TEXT NOT NULL,
    external_key     TEXT,
    external_url     TEXT,
    external_status  TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_synced_at   TIMESTAMPTZ,
    UNIQUE (integration_id, audit_finding_id)
);
CREATE INDEX IF NOT EXISTS workspace_integrations_account_idx ON workspace_integrations (cloud_account_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON workspace_integrations, integration_tickets TO cspm_lambda;
