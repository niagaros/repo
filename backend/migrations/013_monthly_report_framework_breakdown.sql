-- Migration: per-framework before/after breakdown in monthly reports
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- The monthly report already tracked overall score and per-severity
-- before/after (by_severity was already stored). This adds per-framework
-- before/after ("SOC 2 was 88%, now 92%") so the report shows exactly
-- where compliance improved or regressed, not just the aggregate number.
-- Nullable/default so existing historical snapshot rows are left alone
-- rather than backfilled with an invented value.

ALTER TABLE compliance_snapshots
    ADD COLUMN IF NOT EXISTS by_framework JSONB DEFAULT '{}'::jsonb;

GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_snapshots TO cspm_lambda;
