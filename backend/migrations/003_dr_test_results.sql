-- Migration: dr_test_results table
-- Run as cspm_admin (the RDS superuser / schema owner)
--
-- Stores one row per disaster-recovery restore test actually performed
-- (RDS point-in-time restore, DynamoDB point-in-time restore, etc.).
-- These are real, dated events with measured RPO/RTO — this table exists
-- specifically so the dashboard can show real numbers instead of them
-- being typed into the frontend.

CREATE TABLE IF NOT EXISTS dr_test_results (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id      UUID        NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    resource_type         VARCHAR(50) NOT NULL,   -- 'rds-instance' | 'dynamodb-table'
    resource_name         VARCHAR(255) NOT NULL,
    rpo_seconds           INTEGER,                -- measured gap between now and latest restorable point, at test time
    rto_seconds           INTEGER,                -- measured wall-clock restore duration
    data_integrity_match  BOOLEAN,
    method                TEXT,                   -- the exact command used, for reproducibility
    tested_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS dr_test_results_account_idx ON dr_test_results(cloud_account_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON dr_test_results TO cspm_lambda;
