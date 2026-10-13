-- Workspace integrations: a table that already exists in production but
-- was never written down.
--
-- The Jira and Monday.com integration (issue #279) creates this table from
-- inside its own Lambda, through a CREATE TABLE IF NOT EXISTS that runs on
-- an "action": "migrate" call. The result is a table that is real in
-- production, invisible in this repository, and absent from the test
-- harness — which builds its schema from these files. Any code here that
-- reads it would pass in production and fail in every test.
--
-- This migration changes nothing in production: the table is already there,
-- so IF NOT EXISTS makes it a no-op. What it changes is the record. The
-- columns below are copied from the handler's own bootstrap statement, so
-- that what runs and what is written down are the same thing.
--
-- The same reasoning applies here as to the fifty-eight hand-created Lambda
-- functions in the Eindverslag's first recommendation, with one difference:
-- this one costs a single file to fix.
CREATE TABLE IF NOT EXISTS workspace_integrations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Scoped to a cloud account rather than an organization, because what
    -- an integration carries across are that account's findings. Reaching
    -- an organization from here therefore goes the long way round, via
    -- cloud_accounts.owner_email -> users.organization_id, the same path
    -- list_organization_cloud_accounts already takes (see migration 002).
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL CHECK (provider IN ('jira', 'monday')),
    site_url         TEXT,
    account_label    TEXT,
    account_email    TEXT,
    project          TEXT,
    -- The name of an AWS Secrets Manager secret, never the token itself.
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

CREATE INDEX IF NOT EXISTS workspace_integrations_account_idx
    ON workspace_integrations (cloud_account_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON workspace_integrations, integration_tickets TO cspm_lambda;
