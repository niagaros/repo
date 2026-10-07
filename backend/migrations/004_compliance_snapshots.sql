-- Migration: compliance_snapshots table
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Stores one row per monthly compliance snapshot for a cloud account, so the
-- monthly report generator has a real prior data point to diff against for
-- trend data (score delta, newly-introduced findings, newly-resolved
-- findings) instead of only ever describing the current instant. failing_keys
-- is the full (check_id, resource_id) pair list at snapshot time — that's
-- what makes a real new/resolved diff possible on the next run, not just a
-- change in the aggregate counts.

CREATE TABLE IF NOT EXISTS compliance_snapshots (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    total_checks     INTEGER      NOT NULL,
    passed           INTEGER      NOT NULL,
    failed           INTEGER      NOT NULL,
    by_severity      JSONB        NOT NULL DEFAULT '{}',
    failing_keys     JSONB        NOT NULL DEFAULT '[]',  -- [{"check_id":..,"resource_id":..,"resource_name":..,"severity":..,"title":..}]
    report_s3_key    TEXT,
    generated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS compliance_snapshots_account_idx ON compliance_snapshots(cloud_account_id, generated_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_snapshots TO cspm_lambda;
