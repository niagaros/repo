-- Migration: tag compliance_snapshots rows by how they were produced
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Originally compliance_snapshots only got a row once a month, from the
-- report generator itself — which meant the monthly report could only ever
-- diff "right now" against "the same moment last month," with zero
-- visibility into what happened in between (e.g. a mid-month regression
-- that got fixed again before the next monthly trigger). Now the
-- orchestrator inserts a 'scan' row after every completed scan cycle
-- (potentially many per month), and the monthly report inserts a
-- 'monthly_report' row — so the report can compute a real min/max/volatility
-- across the whole period, and diff against the oldest snapshot in the
-- window (state at the start of the period) instead of just the last one.

ALTER TABLE compliance_snapshots
    ADD COLUMN IF NOT EXISTS snapshot_type VARCHAR(20) NOT NULL DEFAULT 'scan';

CREATE INDEX IF NOT EXISTS compliance_snapshots_account_type_idx
    ON compliance_snapshots(cloud_account_id, snapshot_type, generated_at DESC);
